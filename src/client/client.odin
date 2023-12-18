package client

import openssl "../../deps/openssl"
import "../domain"

import "core:bufio"
import "core:log"
import "core:mem"
import "core:net"
import "core:os"
import "core:time"

Client :: struct {
	socket:      Communication,
	read_buffer: Buffer,
}

Frame :: struct {
	opcode:      Opcode,
	payload_len: uint,
	mask:        bool,
	fin:         bool,
	payload:     []byte,
	mask_key:    [4]byte,
}

connect :: proc(target: string, allocator := context.allocator) -> (res: Response, err: Error) {
	r: Request
	request_init(&r)
	defer request_destroy(&r)
	return request(target, &r, allocator)
}

write :: proc(client: ^Client, data: []byte) -> (bytes_written: int, err: Error) {
	switch sock in client.socket {
	case SSL_Communication:
		bytes_written := openssl.SSL_write(sock.ssl, raw_data(data), i32(len(data)))
		// TODO: create error enum for openssl lib
		return int(bytes_written), nil
	case net.TCP_Socket:
		return net.send_tcp(sock, data)
	}
	log.error("what?", client.socket)
	os.exit(1)
}

@(private = "file")
read :: proc(client: ^Client, buffer: ^[]byte, index: int) -> (bytes_read: int, err: Error) {
	switch sock in client.socket {
	case SSL_Communication:
		bytes_read := openssl.SSL_read(sock.ssl, raw_data(buffer[index:]), i32(len(buffer[index:])))
		// TODO: create error enum for openssl lib
		return int(bytes_read), nil
	case net.TCP_Socket:
		return net.recv_tcp(sock, buffer^[index:])
	}
	os.exit(1)
}

// import "core:mem"

OnMessage :: proc(msg: Frame, err: Error, allocator := context.allocator)

run :: proc(client: ^Client, handle_message: OnMessage) -> (msg: Frame, err: Error) {
	recv_buffer := make([]byte, 32 * mem.Kilobyte)
	buffer := Buffer{}
	for {
		bytes_read := read(client, &recv_buffer, buffer.i) or_return
		t1 := time.now()
		client.read_buffer = Buffer {
			data = recv_buffer[:buffer.i + bytes_read],
			i    = 0,
		}
		cont := true
		for cont {
			frame, e := parse_frame(&client.read_buffer)
			#partial switch v in e {
			case FrameNotComplete:
				buffer = Buffer{v.i, 0, v.rest}
				copy(recv_buffer[:len(buffer.data)], buffer.data[:])
				buffer.data = {}
				cont = false
			case EOF:
				cont = false
				buffer = {}
			case nil:
				handle_message(frame, v)
			case:
				log.error(frame)
				log.error(string(frame.payload))
				os.exit(1)
			}
		}
	}
}
