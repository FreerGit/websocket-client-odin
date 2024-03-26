package client

import openssl "../../deps/openssl"
import "../domain"

import "core:bufio"
import "core:log"
import "core:mem"
import "core:net"
import "core:os"
import "core:strconv"
import "core:time"

Client :: struct {
	socket:      Communication,
	allocator:   mem.Allocator,
	read_buffer: Buffer, // @TODO remove
}

client_init :: proc(allocator := context.allocator) -> Client {
	return {allocator = allocator}
}

client_deinit :: proc(client: ^Client) {
	mem.free_all(client.allocator)
}

client_connect :: proc(client: ^Client, url: string) -> (conn: Connection, err: Error) {
	r: Request
	request_init(&r)
	defer request_destroy(&r)
	res := request(url, &r, client.allocator) or_return

	arena := mem.Arena{}
	arena_allocator := mem.arena_allocator(&arena)
	return {com = res._socket, arena = arena_allocator}, nil
}


Frame :: struct {
	opcode:      Opcode,
	payload_len: uint,
	mask:        bool,
	fin:         bool,
	payload:     []byte,
	mask_key:    [4]byte,
}

// connect :: proc(target: string, allocator := context.allocator) -> (res: Response, err: Error) {

// }


// @(private = "file")
// read :: proc(client: ^Client, buffer: ^[]byte, index: int) -> (bytes_read: int, err: Error) {
// 	switch sock in client.socket {
// 	case SSL_Communication:
// 		bytes_read := openssl.SSL_read(sock.ssl, raw_data(buffer[index:]), i32(len(buffer[index:])))
// 		// TODO: create error enum for openssl lib
// 		return int(bytes_read), nil
// 	case net.TCP_Socket:
// 		return net.recv_tcp(sock, buffer^[index:])
// 	}
// 	os.exit(1)

// }

client_receive :: proc(client: ^Client) -> (msg: string, err: Error) {
	for {
		// header, err := receive_header(&client)
	}
	return "", nil

	// recv_buffer := make([]byte, 32 * mem.Kilobyte)
	// buffer := Buffer{}
	// for {
	// 	bytes_read := read(client, &recv_buffer, buffer.i) or_return
	// 	t1 := time.now()
	// 	client.read_buffer = Buffer {
	// 		data = recv_buffer[:buffer.i + bytes_read],
	// 		i    = 0,
	// 	}
	// 	cont := true
	// 	for cont {
	// 		frame, e := parse_frame(&client.read_buffer)
	// 		#partial switch v in e {
	// 		case FrameNotComplete:
	// 			buffer = Buffer{v.i, 0, v.rest}
	// 			copy(recv_buffer[:len(buffer.data)], buffer.data[:])
	// 			buffer.data = {}
	// 			cont = false
	// 		case EOF:
	// 			cont = false
	// 			buffer = {}
	// 		case nil:
	// 			return string(frame.payload), nil
	// 		// handle_message(frame, v)
	// 		case:
	// 			log.error(e)
	// 			log.error(frame)
	// 			log.error(string(frame.payload))
	// 			os.exit(1)
	// 		}
	// 	}
	// }
	// return "", nil
}
