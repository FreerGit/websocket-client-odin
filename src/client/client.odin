package client

import openssl "../../deps/odin-http/openssl"
import "../domain"

import "core:bufio"
import "core:log"
import "core:mem"
import "core:os"
import "core:time"


ClientTLS :: struct {
	socket:      SSL_Communication,
	read_buffer: Buffer,
	// fragment_buffer: Buffer,
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
	// offset := 0
	recv_buffer := make([]byte, 32 * mem.Kilobyte) // res._socket
	buffer := Buffer{}
	for {
		bytes_read := openssl.SSL_read(
			client.socket.ssl,
			raw_data(recv_buffer[buffer.i:]),
			i32(len(recv_buffer[buffer.i:])),
		)
		t1 := time.now()
		client.read_buffer = Buffer {
			data = recv_buffer[:i32(buffer.i) + bytes_read],
			i    = 0,
		}
		cont := true
		n := 0
		for cont {
			frame, e := parse_frame(&client.read_buffer)
			#partial switch v in e {
			case FrameNotComplete:
				// log.error("HIT NOTCOMPLETE")
				// log.error(string(client.fragment_buffer.data))
				buffer = Buffer{v.i, 0, v.rest}
				// for x, i in buffer.data {
				// 	recv_buffer[i] = x
				// }
				copy(recv_buffer[:len(buffer.data)], buffer.data[:])
				buffer.data = {}
				// log.error(string(client.fragment_buffer.data))
				cont = false
			// os.exit(1)
			case EOF:
				cont = false
				buffer = {}
			case nil:
				n += 1
				log.error("??")
				if n > 40 {
					os.exit(1)
				}
				handle_message(frame, v)
			case:
				log.error("|")
				os.exit(1)
			}
			// handle_message(frame, err)
		}

		t2 := time.now()

		log.debug(time.duration_nanoseconds(time.diff(t1, t2)))
	}

}

//


// OnMessage :: proc(text: string, err: Error)
