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
	_body_err: Body_Error,
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
	socket := net.dial_tcp(endpoint) or_return

	// HTTPS using openssl.
	if url.scheme == "https" || url.scheme == "wss" {
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

Body_Error :: enum {
	None,
	No_Length,
	Invalid_Length,
	Too_Long,
	Scan_Failed,
	Invalid_Chunk_Size,
	Invalid_Trailer_Header,
}

// Any non-special body, could have been a chunked body that has been read in fully automatically.
// Depending on the return value for 'was_allocation' of the parse function, this is either an
// allocated string that you should delete or a slice into the body.
Body_Plain :: string

// A URL encoded body, map, keys and values are fully allocated on the allocator given to the parsing function,
// And should be deleted by you.
Body_Url_Encoded :: map[string]string

Body_Type :: union {
	Body_Plain,
	Body_Url_Encoded,
	Body_Error,
}

// Frees the memory allocated by parsing the body.
// was_allocation is returned by the body parsing procedure.
body_destroy :: proc(body: Body_Type, was_allocation: bool) {
	switch b in body {
	case Body_Plain:
		if was_allocation do delete(b)
	case Body_Url_Encoded:
		for k, v in b {
			delete(k)
			delete(v)
		}
		delete(b)
	case Body_Error:
	}
}

// Frees the response, closes the connection.
// Optionally pass the response_body returned 'body' and 'was_allocation' to destroy it too.
response_destroy :: proc(res: ^Response, body: Maybe(Body_Type) = nil, was_allocation := false) {
	// Header keys are allocated, values are slices into the body.
	// NOTE: this is fine because we don't add any headers with `headers_set_unsafe()`.
	// If we did, we wouldn't know if the key was allocated or a literal.
	// We also set the headers to readonly before giving them to the user so they can't add any either.
	for k in res.headers._kv {
		delete(k)
	}

	delete(res.headers._kv)

	bufio.scanner_destroy(&res._body)

	// Cookies only contain slices to memory inside the scanner body.
	// So just deleting the array will be enough.
	// delete(res.cookies)

	if body != nil {
		body_destroy(body.(Body_Type), was_allocation)
	}

	// We close now and not at the time we got the response because reading the body,
	// could make more reads need to happen (like with chunked encoding).
	switch comm in res._socket {
	case net.TCP_Socket:
		net.close(comm)
	case SSL_Communication:
		openssl.SSL_free(comm.ssl)
		openssl.SSL_CTX_free(comm.ctx)
		net.close(comm.socket)
	}
}

// Body :: string

// Body_Callback :: #type proc(user_data: rawptr, body: Body, err: Body_Error)

// Body_Error :: bufio.Scanner_Error

// Retrieves the response's body, can only be called once.
// Free the returned body using body_destroy().
response_body :: proc(
	res: ^Response,
	max_length := -1,
	allocator := context.allocator,
) -> (
	body: Body_Type,
	was_allocation: bool,
	err: Body_Error,
) {
	defer res._body_err = err
	assert(res._body_err == nil)
	body, was_allocation, err = _parse_body(&res.headers, &res._body, max_length, allocator)
	return
}

_parse_body :: proc(
	headers: ^domain.Headers,
	_body: ^bufio.Scanner,
	max_length := -1,
	allocator := context.allocator,
) -> (
	body: Body_Type,
	was_allocation: bool,
	err: Body_Error,
) {
	// See [RFC 7230 3.3.3](https://www.rfc-editor.org/rfc/rfc7230#section-3.3.3) for the rules.
	// Point 3 paragraph 3 and point 4 are handled before we get here.

	enc, has_enc := domain.headers_get_unsafe(headers^, "transfer-encoding")
	length, has_length := domain.headers_get_unsafe(headers^, "content-length")
	switch {
	case has_enc && strings.has_suffix(enc, "chunked"):
		was_allocation = true
		body = _response_body_chunked(headers, _body, max_length, allocator) or_return

	case has_length:
		body = _response_body_length(_body, max_length, length) or_return

	case:
		body = _response_till_close(_body, max_length) or_return
	}

	// Automatically decode url encoded bodies.
	if typ, ok := domain.headers_get_unsafe(headers^, "content-type");
	   ok && typ == "application/x-www-form-urlencoded" {
		plain := body.(Body_Plain)
		defer if was_allocation do delete(plain)

		keyvalues := strings.split(plain, "&", allocator)
		defer delete(keyvalues, allocator)

		queries := make(Body_Url_Encoded, len(keyvalues), allocator)
		for keyvalue in keyvalues {
			seperator := strings.index(keyvalue, "=")
			if seperator == -1 { 	// The keyvalue has no value.
				queries[keyvalue] = ""
				continue
			}

			key, key_decoded_ok := net.percent_decode(keyvalue[:seperator], allocator)
			if !key_decoded_ok {
				log.warnf("url encoded body key %q could not be decoded", keyvalue[:seperator])
				continue
			}

			val, val_decoded_ok := net.percent_decode(keyvalue[seperator + 1:], allocator)
			if !val_decoded_ok {
				log.warnf("url encoded body value %q for key %q could not be decoded", keyvalue[seperator + 1:], key)
				continue
			}

			queries[key] = val
		}

		body = queries
	}

	return
}

_response_till_close :: proc(_body: ^bufio.Scanner, max_length: int) -> (string, Body_Error) {
	_body.max_token_size = max_length
	defer _body.max_token_size = bufio.DEFAULT_MAX_SCAN_TOKEN_SIZE

	_body.split =
	proc(data: []byte, at_eof: bool) -> (advance: int, token: []byte, err: bufio.Scanner_Error, final_token: bool) {
		if at_eof {
			return len(data), data, nil, true
		}

		return
	}
	defer _body.split = bufio.scan_lines

	if !bufio.scanner_scan(_body) {
		if bufio.scanner_error(_body) == .Too_Long {
			log.debug("HERE")
			return "", .Too_Long
		}

		return "", .Scan_Failed
	}

	return bufio.scanner_text(_body), .None
}

// "Decodes" a response body based on the content length header.
// Meant for internal usage, you should use `client.response_body`.
_response_body_length :: proc(_body: ^bufio.Scanner, max_length: int, len: string) -> (string, Body_Error) {
	ilen, lenok := strconv.parse_int(len, 10)
	if !lenok {
		return "", .Invalid_Length
	}

	if max_length > -1 && ilen > max_length {
		return "", .Too_Long
	}

	if ilen == 0 {
		return "", nil
	}

	// user_index is used to set the amount of bytes to scan in scan_num_bytes.
	context.user_index = ilen

	_body.max_token_size = ilen
	defer _body.max_token_size = bufio.DEFAULT_MAX_SCAN_TOKEN_SIZE

	_body.split = scan_num_bytes
	defer _body.split = bufio.scan_lines

	log.debugf("scanning %i bytes body", ilen)

	if !bufio.scanner_scan(_body) {
		return "", .Scan_Failed
	}

	return bufio.scanner_text(_body), .None
}

// "Decodes" a chunked transfer encoded request body.
// Meant for internal usage, you should use `client.response_body`.
//
// RFC 7230 4.1.3 pseudo-code:
//
// length := 0
// read chunk-size, chunk-ext (if any), and CRLF
// while (chunk-size > 0) {
//    read chunk-data and CRLF
//    append chunk-data to decoded-body
//    length := length + chunk-size
//    read chunk-size, chunk-ext (if any), and CRLF
// }
// read trailer field
// while (trailer field is not empty) {
//    if (trailer field is allowed to be sent in a trailer) {
//    	append trailer field to existing header fields
//    }
//    read trailer-field
// }
// Content-Length := length
// Remove "chunked" from Transfer-Encoding
// Remove Trailer from existing header fields
_response_body_chunked :: proc(
	headers: ^domain.Headers,
	_body: ^bufio.Scanner,
	max_length: int,
	allocator := context.allocator,
) -> (
	body: string,
	err: Body_Error,
) {
	body_buff: bytes.Buffer

	bytes.buffer_init_allocator(&body_buff, 0, 0, allocator)
	defer if err != nil do bytes.buffer_destroy(&body_buff)

	for {
		if !bufio.scanner_scan(_body) {
			return "", .Scan_Failed
		}

		size_line := bufio.scanner_bytes(_body)

		// If there is a semicolon, discard everything after it,
		// that would be chunk extensions which we currently have no interest in.
		if semi := bytes.index_byte(size_line, ';'); semi > -1 {
			size_line = size_line[:semi]
		}

		size, ok := strconv.parse_int(string(size_line), 16)
		if !ok {
			err = .Invalid_Chunk_Size
			return
		}
		if size == 0 do break

		if max_length > -1 && bytes.buffer_length(&body_buff) + size > max_length {
			return "", .Too_Long
		}

		// user_index is used to set the amount of bytes to scan in scan_num_bytes.
		context.user_index = size

		_body.max_token_size = size
		_body.split = scan_num_bytes

		if !bufio.scanner_scan(_body) {
			return "", .Scan_Failed
		}

		_body.max_token_size = bufio.DEFAULT_MAX_SCAN_TOKEN_SIZE
		_body.split = bufio.scan_lines

		bytes.buffer_write(&body_buff, bufio.scanner_bytes(_body))

		// Read empty line after chunk.
		if !bufio.scanner_scan(_body) {
			return "", .Scan_Failed
		}
		assert(bufio.scanner_text(_body) == "")
	}

	// Read trailing empty line (after body, before trailing headers).
	if !bufio.scanner_scan(_body) || bufio.scanner_text(_body) != "" {
		return "", .Scan_Failed
	}

	// Keep parsing the request as line delimited headers until we get to an empty line.
	for {
		// If there are no trailing headers, this case is hit.
		if !bufio.scanner_scan(_body) {
			break
		}

		line := bufio.scanner_text(_body)

		// The first empty line denotes the end of the headers section.
		if line == "" {
			break
		}

		key, ok := domain.header_parse(headers, line)
		if !ok {
			return "", .Invalid_Trailer_Header
		}

		// A recipient MUST ignore (or consider as an error) any fields that are forbidden to be sent in a trailer.
		if !domain.header_allowed_trailer(key) {
			domain.headers_delete(headers, key)
		}
	}

	if domain.headers_has(headers^, "trailer") {
		domain.headers_delete_unsafe(headers, "trailer")
	}

	te := strings.trim_suffix(domain.headers_get_unsafe(headers^, "transfer-encoding"), "chunked")
	domain.headers_set_unsafe(headers, "transfer-encoding", te)

	return bytes.buffer_to_string(&body_buff), .None
}

// A scanner bufio.Split_Proc implementation to scan a given amount of bytes.
// The amount of bytes should be set in the context.user_index.
@(private)
scan_num_bytes :: proc(
	data: []byte,
	at_eof: bool,
) -> (
	advance: int,
	token: []byte,
	err: bufio.Scanner_Error,
	final_token: bool,
) {
	n := context.user_index // Set context.user_index to the amount of bytes to read.
	if at_eof && len(data) < n {
		return
	}

	if len(data) < n {
		return
	}

	return n, data[:n], nil, false
}
