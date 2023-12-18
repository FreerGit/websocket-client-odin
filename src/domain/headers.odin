package domain

import "core:bytes"
import "core:encoding/base64"
import "core:intrinsics"
import "core:math/rand"
import "core:strings"

// A case-insensitive ASCII map for storing headers.
Headers :: struct {
	_kv:      map[string]string,
	readonly: bool,
}

headers_init :: proc(h: ^Headers, allocator := context.temp_allocator) {
	h._kv.allocator = allocator
}

headers_count :: #force_inline proc(h: Headers) -> int {
	return len(h._kv)
}

/*
Sets a header, given key is copied and turned into lowercase.
*/
headers_set :: proc(h: ^Headers, k: string, v: string, loc := #caller_location) -> string {
	if h.readonly {
		panic("these headers are readonly, did you accidentally try to set a header on the request?", loc)
	}

	// TODO/PERF: only allocate if the key contains uppercase.

	allocator := h._kv.allocator if h._kv.allocator.procedure != nil else context.allocator
	l := make([]byte, len(k), allocator)

	for b, i in transmute([]byte)k {
		if b >= 'A' && b <= 'Z' {
			l[i] = b + 32
		} else {
			l[i] = b
		}
	}

	h._kv[string(l)] = v
	return string(l)
}

/*
Unsafely set header, given key is assumed to be a lowercase string.
*/
headers_set_unsafe :: #force_inline proc(h: ^Headers, k: string, v: string) {
	assert(!h.readonly)
	h._kv[k] = v
}

headers_get :: proc(h: Headers, k: string) -> (string, bool) #optional_ok {
	l := intrinsics.alloca(len(k), 1)[:len(k)]
	for b, i in transmute([]byte)k {
		if b >= 'A' && b <= 'Z' {
			l[i] = b + 32
		} else {
			l[i] = b
		}
	}

	return h._kv[string(l)]
}

/*
Unsafely get header, given key is assumed to be a lowercase string.
*/
headers_get_unsafe :: #force_inline proc(h: Headers, k: string) -> (string, bool) #optional_ok {
	return h._kv[k]
}

headers_has :: proc(h: Headers, k: string) -> bool {
	l := intrinsics.alloca(len(k), 1)[:len(k)]
	for b, i in transmute([]byte)k {
		if b >= 'A' && b <= 'Z' {
			l[i] = b + 32
		} else {
			l[i] = b
		}
	}

	return string(l) in h._kv
}

/*
Unsafely check for a header, given key is assumed to be a lowercase string.
*/
headers_has_unsafe :: #force_inline proc(h: Headers, k: string) -> bool {
	return k in h._kv
}

headers_delete :: proc(h: ^Headers, k: string) {
	l := intrinsics.alloca(len(k), 1)[:len(k)]
	for b, i in transmute([]byte)k {
		if b >= 'A' && b <= 'Z' {
			l[i] = b + 32
		} else {
			l[i] = b
		}
	}

	delete_key(&h._kv, string(l))
}

/*
Unsafely delete a header, given key is assumed to be a lowercase string.
*/
headers_delete_unsafe :: #force_inline proc(h: ^Headers, k: string) {
	delete_key(&h._kv, k)
}

/* Common Helpers */

headers_set_content_type :: #force_inline proc(h: ^Headers, ct: string) {
	headers_set_unsafe(h, "content-type", ct)
}

headers_set_close :: #force_inline proc(h: ^Headers) {
	headers_set_unsafe(h, "connection", "close")
}

header_parse :: proc(
	headers: ^Headers,
	line: string,
	allocator := context.temp_allocator,
) -> (
	key: string,
	ok: bool,
) {
	// Preceding spaces should not be allowed.
	(len(line) > 0 && line[0] != ' ') or_return

	colon := strings.index_byte(line, ':')
	(colon > 0) or_return

	// There must not be a space before the colon.
	(line[colon - 1] != ' ') or_return

	// TODO/PERF: only actually relevant/needed if the key is one of these.
	has_host := headers_has_unsafe(headers^, "host")
	cl, has_cl := headers_get_unsafe(headers^, "content-length")

	value := strings.trim_space(line[colon + 1:])
	key = headers_set(headers, line[:colon], value)

	// RFC 7230 5.4: Server MUST respond with 400 to any request
	// with multiple "Host" header fields.
	if key == "host" && has_host {
		return
	}

	// RFC 7230 3.3.3: If a message is received without Transfer-Encoding and with
	// either multiple Content-Length header fields having differing
	// field-values or a single Content-Length header field having an
	// invalid value, then the message framing is invalid and the
	// recipient MUST treat it as an unrecoverable error.
	if key == "content-length" && has_cl && cl != value {
		return
	}

	ok = true
	return
}

// Validates the headers, use `headers_validate_for_server` if these are request headers
// that should be validated from the server side.
headers_validate :: proc(headers: ^Headers) -> bool {
	// RFC 7230 3.3.3: If a Transfer-Encoding header field
	// is present in a request and the chunked transfer coding is not
	// the final encoding, the message body length cannot be determined
	// reliably; the server MUST respond with the 400 (Bad Request)
	// status code and then close the connection.
	if enc_header, ok := headers_get_unsafe(headers^, "transfer-encoding"); ok {
		strings.has_suffix(enc_header, "chunked") or_return
	}

	// RFC 7230 3.3.3: If a message is received with both a Transfer-Encoding and a
	// Content-Length header field, the Transfer-Encoding overrides the
	// Content-Length.  Such a message might indicate an attempt to
	// perform request smuggling (Section 9.5) or response splitting
	// (Section 9.4) and ought to be handled as an error.
	if headers_has_unsafe(headers^, "transfer-encoding") && headers_has_unsafe(headers^, "content-length") {
		headers_delete_unsafe(headers, "content-length")
	}

	return true
}

set_websocket_connection_headers :: proc(headers: ^Headers, host: string) -> ^Headers {
	key_bytes: [16]byte
	bytes_filled := rand.read(key_bytes[:])
	assert(bytes_filled == len(key_bytes))
	key := base64.encode(key_bytes[:])

	headers_set(headers, "Host", host)
	headers_set(headers, "Upgrade", "websocket")
	headers_set(headers, "Connection", "Upgrade")
	headers_set(headers, "Sec-WebSocket-Version", "13")
	headers_set(headers, "Sec-WebSocket-Key", key)
	return headers
}


// Returns if this is a valid trailer header.
//
// RFC 7230 4.1.2:
// A sender MUST NOT generate a trailer that contains a field necessary
// for message framing (e.g., Transfer-Encoding and Content-Length),
// routing (e.g., Host), request modifiers (e.g., controls and
// conditionals in Section 5 of [RFC7231]), authentication (e.g., see
// [RFC7235] and [RFC6265]), response control data (e.g., see Section
// 7.1 of [RFC7231]), or determining how to process the payload (e.g.,
// Content-Encoding, Content-Type, Content-Range, and Trailer).
header_allowed_trailer :: proc(key: string) -> bool {
	// odinfmt:disable
    return (
        // Message framing:
        key != "transfer-encoding" &&
        key != "content-length" &&
        // Routing:
        key != "host" &&
        // Request modifiers:
        key != "if-match" &&
        key != "if-none-match" &&
        key != "if-modified-since" &&
        key != "if-unmodified-since" &&
        key != "if-range" &&
        // Authentication:
        key != "www-authenticate" &&
        key != "authorization" &&
        key != "proxy-authenticate" &&
        key != "proxy-authorization" &&
        key != "cookie" &&
        key != "set-cookie" &&
        // Control data:
        key != "age" &&
        key != "cache-control" &&
        key != "expires" &&
        key != "date" &&
        key != "location" &&
        key != "retry-after" &&
        key != "vary" &&
        key != "warning" &&
        // How to process:
        key != "content-encoding" &&
        key != "content-type" &&
        key != "content-range" &&
        key != "trailer")
	// odinfmt:enable
}

Version :: struct {
	major: u8,
	minor: u8,
}


// Parses an HTTP version string according to RFC 7230, section 2.6.
version_parse :: proc(s: string) -> (version: Version, ok: bool) {
	(len(s) > 5) or_return
	(s[:5] == "HTTP/") or_return
	version.major = u8(int(rune(s[5])) - '0')
	if len(s) > 6 {
		(s[6] == '.') or_return
		version.minor = u8(int(rune(s[7])) - '0')
	}
	ok = true
	return
}
