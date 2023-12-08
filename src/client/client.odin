package client

import openssl "../../deps/odin-http/openssl"
import "../domain"


import "core:bufio"
import "core:bytes"
import "core:crypto"
import "core:encoding/base64"
import "core:fmt"
import "core:io"
import "core:log"
import "core:math/rand"
import "core:mem"
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

str := "{\"op\": \"subscribe\",\"args\": [\"orderbook.50.BTCUSDT\"]}"


main :: proc() {
	argv := os.args

	context.logger = log.create_console_logger()

	target := "wss://stream.bybit.com/v5/public/spot"
	res, err := connect(target)


	recv_buffer := make([]byte, 256 * mem.Megabyte) // res._socket
	fragment_serialization_buffer: [256 * mem.Kilobyte]byte
	mask_key: [4]byte
	crypto.rand_bytes(mask_key[:])

	b: bytes.Buffer
	bytes.buffer_init_string(&b, str)

	sub_fragment := Websocket_Fragment {
		data = Text_Data{payload = bytes.buffer_to_bytes(&b)},
		final = true,
		mask = true,
		mask_key = mask_key,
	}
	// log.debug(len(transmute([]u8)str))

	#partial switch comm in res._socket {
	// case net.TCP_Socket:
	// stream = tcp_stream(comm)
	case SSL_Communication:
		serialized_data, serialize_error := serialize_websocket_fragment(
			fragment_serialization_buffer[:],
			sub_fragment,
		)
		openssl.SSL_write(comm.ssl, raw_data(serialized_data), i32(len(serialized_data)))
		for {
			openssl.SSL_read(comm.ssl, raw_data(recv_buffer[:]), i32(len(recv_buffer)))
			t := time.now()
			frame, remaining_data, frame_parse_error := parse_websocket_fragment(recv_buffer[:])
			if frame_parse_error != nil {
				fmt.printf("Error when parsing frame: %v\n", frame_parse_error)

				os.exit(1)
			}
			t1 := time.now()
			fmt.println(time.duration_nanoseconds(time.diff(t, t1)))

			#partial switch v in frame.data {
			case Text_Data:
			// log.debug(string(v.payload))
			}


		}

	// bytes_received, recv_error := net.recv_tcp(comm., recv_buffer[:])

	}


	defer response_destroy(&res)
	body, allocation, berr := response_body(&res)
	if berr != nil {
		fmt.printf("Error retrieving response body: %s", berr)
		return
	}
	defer body_destroy(body, allocation)
	log.debug("hej")
	fmt.println(body)
	// bufio.
}
