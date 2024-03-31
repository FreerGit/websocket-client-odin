//+ private
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


Error :: union #shared_nil {
	bufio.Scanner_Error,
	mem.Allocator_Error,
	Request_Error,
	Connection_Error,
}


str := "{\"op\": \"subscribe\",\"args\": [\"orderbook.1.BTCUSDT\"]}"

import "core:encoding/json"
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
	b:   [][2]f64,
	a:   [][2]f64,
}


main :: proc() {

	argv := os.args

	context.logger = log.create_console_logger()

	// scratch := mem.Scratch_Allocator{}
	// fba := mem.scratch_allocator_init(&scratch, 8 * 64 * 1024)

	client := client_init()
	defer client_deinit(&client)

	connection, err := client_connect(&client, "wss://stream.bybit.com/v5/public/linear")
	if err != nil {
		log.error(err)
	}

	write_err := connection_send(&connection, str)
	log.debug(write_err)
	if write_err != nil {
		log.error(write_err)
		panic("done")
	}

	for {
		msg, recv_err := connection_recv(&connection)
		fmt.println(msg, recv_err)
	}
}
