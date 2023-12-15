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
import "core:slice"
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

Error :: union #shared_nil {
	net.Dial_Error,
	net.Parse_Endpoint_Error,
	net.Network_Error,
	bufio.Scanner_Error,
	Request_Error,
	SSL_Error,
	ParseError,
}


str := "{\"op\": \"subscribe\",\"args\": [\"orderbook.50.BTCUSDT\"]}"

import "core:strings"

handle_message :: proc(frame: Frame, err: Error) {
	if err != nil {
		log.error(frame, err)
		os.exit(1)
	} else {
		str := string(frame.payload)
		if len(str) == 0 {
			log.error("empty")
			os.exit(1)
		} else if !strings.has_suffix(str, "}") {
			log.error("does not end in '}'")
			log.error(str)
			os.exit(1)
		}
		// log.debug(string(frame.payload))
	}
}

main :: proc() {

	argv := os.args

	context.logger = log.create_console_logger()

	target := "wss://stream.bybit.com/v5/public/spot"
	// TODO: should take a client? return a client? change this api
	res, err := connect(target)


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

		// TODO: write function
		fmt.println(openssl.SSL_write(comm.ssl, raw_data(serialized_data), i32(len(serialized_data))))

		// TODO: init function
		// TODO: cleanup function?
		client := ClientTLS {
			socket = comm,
		}

		run(&client, handle_message)


	}


	// defer response_destroy(&res)
	// body, allocation, berr := response_body(&res)
	// if berr != nil {
	// 	fmt.printf("Error retrieving response body: %s", berr)
	// 	return
	// }
	// defer body_destroy(body, allocation)
	// log.debug("hej")
	// fmt.println(body)
	// // bufio.
}
