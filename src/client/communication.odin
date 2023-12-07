//+private
package client

import http "../../deps/odin-http/"
import openssl "../../deps/odin-http/openssl"
import "../domain"

import "core:bufio"
import "core:bytes"
import "core:c"
import "core:io"
import "core:log"
import "core:net"
import "core:strconv"
import "core:strings"


// Initializes the request with sane defaults using the given allocator.
request_init :: proc(r: ^Request, allocator := context.allocator) {
	domain.headers_init(&r.headers)
	bytes.buffer_init_allocator(&r.body, 0, 0, allocator)
}

request_destroy :: proc(r: ^Request) {
	delete(r.headers._kv)
	bytes.buffer_destroy(&r.body)
}

format_request :: proc(target: domain.URL, request: ^Request, allocator := context.allocator) -> (buf: bytes.Buffer) {
	// Responses are on average at least 100 bytes, so lets start there, but add the body's length.
	bytes.buffer_init_allocator(&buf, 0, bytes.buffer_length(&request.body) + 100, allocator)

	bytes.buffer_write_string(&buf, "GET ")
	bytes.buffer_write_string(&buf, target.path)
	bytes.buffer_write_string(&buf, " HTTP/1.1\r\n")

	for key, value in request.headers._kv {
		bytes.buffer_write_string(&buf, key)
		bytes.buffer_write_string(&buf, ": ")
		bytes.buffer_write_string(&buf, value)
		bytes.buffer_write_string(&buf, "\r\n")
	}

	for header, value in request.headers._kv {
		bytes.buffer_write_string(&buf, header)
		bytes.buffer_write_string(&buf, ": ")

		// Escape newlines in headers, if we don't, an attacker can find an endpoint
		// that returns a header with user input, and inject headers into the response.
		esc_value, was_allocation := strings.replace_all(value, "\n", "\\n", allocator)
		defer if was_allocation do delete(esc_value)

		bytes.buffer_write_string(&buf, esc_value)
		bytes.buffer_write_string(&buf, "\r\n")
	}


	bytes.buffer_write_string(&buf, "\r\n")

	bytes.buffer_write(&buf, bytes.buffer_to_bytes(&request.body))
	return
}

parse_endpoint :: proc(target: string) -> (url: domain.URL, endpoint: net.Endpoint, err: net.Network_Error) {
	url = domain.url_parse(target)
	host_or_endpoint := net.parse_hostname_or_endpoint(url.host) or_return

	switch t in host_or_endpoint {
	case net.Endpoint:
		endpoint = t
		return
	case net.Host:
		ep4, ep6 := net.resolve(t.hostname) or_return
		endpoint = ep4 if ep4.address != nil else ep6

		endpoint.port = t.port
		if endpoint.port == 0 {
			endpoint.port = url.scheme == "https" || url.scheme == "wss" ? 443 : 80
		}
		return
	case:
		unreachable()
	}
}

SSL_Communication :: struct {
	socket: net.TCP_Socket,
	ssl:    ^openssl.SSL,
	ctx:    ^openssl.SSL_CTX,
}

Communication :: union {
	net.TCP_Socket, // HTTP.
	SSL_Communication, // HTTPS.
}

Response :: struct {
	status:    domain.Status,
	// headers and cookies should be considered read-only, after a response is returned.
	headers:   domain.Headers,
	_socket:   Communication,
	_body:     bufio.Scanner,
	_body_err: http.Body_Error,
}


parse_response :: proc(socket: Communication, allocator := context.allocator) -> (res: Response, err: Error) {
	res._socket = socket

	stream: io.Stream
	switch comm in socket {
	case net.TCP_Socket:
		stream = tcp_stream(comm)
	case SSL_Communication:
		stream = ssl_tcp_stream(comm.ssl)
	}

	stream_reader := io.to_reader(stream)
	scanner: bufio.Scanner
	bufio.scanner_init(&scanner, stream_reader, allocator)

	domain.headers_init(&res.headers, allocator)

	if !bufio.scanner_scan(&scanner) {
		err = bufio.scanner_error(&scanner)
		return
	}

	rline_str := bufio.scanner_text(&scanner)
	si := strings.index_byte(rline_str, ' ')

	version, ok := http.version_parse(rline_str[:si])
	if !ok {
		err = Request_Error.Invalid_Response_HTTP_Version
		return
	}

	// Might need to support more versions later.
	if version.major != 1 {
		err = Request_Error.Invalid_Response_HTTP_Version
		return
	}

	res.status, ok = domain.status_from_string(rline_str[si + 1:])
	if !ok {
		err = Request_Error.Invalid_Response_Method
		return
	}

	for {
		if !bufio.scanner_scan(&scanner) {
			err = bufio.scanner_error(&scanner)
			return
		}

		line := bufio.scanner_text(&scanner)
		// Empty line means end of headers.
		if line == "" do break

		key, ok := domain.header_parse(&res.headers, line, allocator)
		if !ok {
			err = Request_Error.Invalid_Response_Header
			return
		}

		// if key == "set-cookie" {
		// 	cookie_str := domain.headers_get_unsafe(res.headers, "set-cookie")
		// 	domain.headers_delete_unsafe(&res.headers, "set-cookie")
		// 	delete(key)

		// 	cookie, ok := http.cookie_parse(cookie_str, allocator)
		// 	if !ok {
		// 		err = Request_Error.Invalid_Response_Cookie
		// 		return
		// 	}

		// 	append(&res.cookies, cookie)
		// }
	}

	if !domain.headers_validate(&res.headers) {
		err = Request_Error.Invalid_Response_Header
		return
	}

	res.headers.readonly = true

	res._body = scanner
	return res, nil
}


request :: proc(target: string, request: ^Request, allocator := context.allocator) -> (res: Response, err: Error) {
	url, endpoint := parse_endpoint(target) or_return
	defer delete(url.queries)

	domain.set_websocket_connection_headers(&request.headers, url.host)
	req_buf := format_request(url, request, allocator)
	defer bytes.buffer_destroy(&req_buf)
	log.debug(request)
	log.debug(endpoint)
	socket := net.dial_tcp(endpoint) or_return

	// HTTPS using openssl.
	if url.scheme == "https" || url.scheme == "wss" {
		log.debug("right path")
		ctx := openssl.SSL_CTX_new(openssl.TLS_client_method())
		ssl := openssl.SSL_new(ctx)
		openssl.SSL_set_fd(ssl, c.int(socket))

		// For servers using SNI for SSL certs (like cloudflare), this needs to be set.
		chostname := strings.clone_to_cstring(url.host, allocator)
		defer delete(chostname)
		openssl.SSL_set_tlsext_host_name(ssl, chostname)

		switch openssl.SSL_connect(ssl) {
		case 2:
			err = SSL_Error.Controlled_Shutdown
			return
		case 1: // success
		case:
			log.debug("fatal")
			err = SSL_Error.Fatal_Shutdown
			return
		}

		buf := bytes.buffer_to_bytes(&req_buf)
		to_write := len(buf)
		for to_write > 0 {
			ret := openssl.SSL_write(ssl, raw_data(buf), c.int(to_write))
			if ret <= 0 {
				err = SSL_Error.SSL_Write_Failed
				return
			}

			to_write -= int(ret)
		}

		return parse_response(SSL_Communication{ssl = ssl, ctx = ctx, socket = socket}, allocator)
	}

	// HTTP, just send the request.
	net.send_tcp(socket, bytes.buffer_to_bytes(&req_buf)) or_return
	return parse_response(socket, allocator)
}


ssl_tcp_stream :: proc(sock: ^openssl.SSL) -> (s: io.Stream) {
	s.data = sock
	s.procedure = _ssl_stream_proc
	return s
}

@(private)
_ssl_stream_proc :: proc(
	stream_data: rawptr,
	mode: io.Stream_Mode,
	p: []byte,
	offset: i64,
	whence: io.Seek_From,
) -> (
	n: i64,
	err: io.Error,
) {
	#partial switch mode {
	case .Query:
		return io.query_utility(io.Stream_Mode_Set{.Query, .Read})
	case .Read:
		ssl := cast(^openssl.SSL)stream_data
		ret := openssl.SSL_read(ssl, raw_data(p), c.int(len(p)))
		if ret <= 0 {
			return 0, .Unexpected_EOF
		}

		return i64(ret), nil
	case:
		err = .Empty
	}
	return
}

// Wraps a tcp socket with a stream.
tcp_stream :: proc(sock: net.TCP_Socket) -> (s: io.Stream) {
	s.data = rawptr(uintptr(sock))
	s.procedure = _socket_stream_proc
	return s
}

@(private)
_socket_stream_proc :: proc(
	stream_data: rawptr,
	mode: io.Stream_Mode,
	p: []byte,
	offset: i64,
	whence: io.Seek_From,
) -> (
	n: i64,
	err: io.Error,
) {
	#partial switch mode {
	case .Query:
		return io.query_utility(io.Stream_Mode_Set{.Query, .Read})
	case .Read:
		sock := net.TCP_Socket(uintptr(stream_data))
		received, recv_err := net.recv_tcp(sock, p)
		n = i64(received)

		#partial switch ex in recv_err {
		case net.TCP_Recv_Error:
			#partial switch ex {
			case .None:
				err = .None
			case .Shutdown, .Not_Connected, .Aborted, .Connection_Closed, .Host_Unreachable, .Timeout:
				log.errorf("unexpected error reading tcp: %s", ex)
				err = .Unexpected_EOF
			case:
				log.errorf("unexpected error reading tcp: %s", ex)
				err = .Unknown
			}
		case nil:
			err = .None
		case:
			assert(false, "recv_tcp only returns TCP_Recv_Error or nil")
		}
	case:
		err = .Empty
	}
	return
}
