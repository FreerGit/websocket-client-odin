package client

import openssl "../../deps/odin-http/openssl"
import "../domain"

import "core:bufio"
import "core:log"
import "core:mem"
import "core:os"


ClientTLS :: struct {
	socket:          SSL_Communication,
	read_buffer:     Buffer,
	fragment_buffer: Buffer,
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

OnMessage :: proc(msg: Frame, err: Error)

run :: proc(client: ^ClientTLS, handle_message: OnMessage) -> (msg: Frame, err: Error) {
	recv_buffer := make([]byte, 256 * mem.Kilobyte) // res._socket
	for {
		bytes_read := openssl.SSL_read(client.socket.ssl, raw_data(recv_buffer[:]), i32(len(recv_buffer)))
		client.read_buffer = Buffer {
			data = recv_buffer[:bytes_read],
			i    = 0,
		}
		cont := true
		n := 0
		for cont {
			frame, e := parse_frame(&client.read_buffer, &client.fragment_buffer)
			#partial switch v in e {
			case FrameNotComplete:
				log.error("HIT NOTCOMPLETE")
				client.fragment_buffer = Buffer{0, v.rest}
				log.error(string(client.fragment_buffer.data))
				cont = false
			// os.exit(1)
			case EOF:
				cont = false
			case nil:
				n += 1
				if n > 40 {
					os.exit(1)
				}
				log.debug(n)
				handle_message(frame, v)
			}
			// handle_message(frame, err)
		}
	}

}

//


// OnMessage :: proc(text: string, err: Error)
