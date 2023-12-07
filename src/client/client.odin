package client

import "../domain"

import "core:bufio"
import "core:bytes"
import "core:crypto"
import "core:encoding/base64"
import "core:fmt"
import "core:log"
import "core:math/rand"
import "core:net"
import "core:os"
import "core:time"

Request :: struct {
	headers: domain.Headers,
	body:    bytes.Buffer,
}

Request_Error :: enum {
	Invalid_Response_HTTP_Version,
	Invalid_Response_Method,
	Invalid_Response_Header,
	Invalid_Response_Cookie,
}

SSL_Error :: enum {
	Controlled_Shutdown,
	Fatal_Shutdown,
	SSL_Write_Failed,
}

Error :: union {
	net.Dial_Error,
	net.Parse_Endpoint_Error,
	net.Network_Error,
	bufio.Scanner_Error,
	Request_Error,
	SSL_Error,
}

connect :: proc(target: string, allocator := context.allocator) -> (res: Response, err: Error) {
	r: Request
	request_init(&r)
	defer request_destroy(&r)
	return request(target, &r, allocator)
}

main :: proc() {
	argv := os.args

	context.logger = log.create_console_logger()

	target := "wss://stream.bybit.com/v5/public/spot"
	res, err := connect(target)
	log.debug(res, err)

	key_bytes: [16]byte
	fmt.println(key_bytes)
	bytes_filled := rand.read(key_bytes[:])
	assert(bytes_filled == len(key_bytes))
	key := base64.encode(key_bytes[:])
	fmt.println(key)
	// fmt.println(host)
}
