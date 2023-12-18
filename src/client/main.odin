package client

import openssl "../../deps/openssl"
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

import "core:encoding/json"
import "core:mem/virtual"
import "core:strings"

OrderbookSmtg :: struct {
	topic: string,
	type:  string,
	data:  SomeUpdate,
	ts:    u64,
	cts:   u64,
}

SomeUpdate :: struct {
	s:   string,
	u:   u64,
	seq: u64,
	b:   [][2]string,
	a:   [][2]string,
}

handle_message :: proc(frame: Frame, err: Error, allocator := context.allocator) {
	if err != nil {
		log.error(frame, err)
		os.exit(1)
	} else {
		str := string(frame.payload)
		@(static)
		ob: OrderbookSmtg
		parse_err := json.unmarshal(frame.payload, &ob, .JSON, allocator)
		if parse_err != nil {
			log.error(parse_err)
		}
		ob = {}
	}
}

main :: proc() {

	argv := os.args

	context.logger = log.create_console_logger()

	target := "wss://stream.bybit.com/v5/public/spot"

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

	serialized_data, serialize_error := serialize_websocket_fragment(
		fragment_serialization_buffer[:],
		sub_fragment,
	)

	// TODO: should take a client? return a client? change this api
	res, err := connect(target)
	if err != nil {
		log.error((err))
	}

	client := Client {
		socket = res._socket,
	}

	bytes_sent, write_err := write(&client, serialized_data)

	run(&client, handle_message)


}
