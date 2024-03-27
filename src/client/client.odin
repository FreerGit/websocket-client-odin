package client

import openssl "../../deps/openssl"
import "../domain"

import "core:bufio"
import "core:mem"
import "core:mem/virtual"
import "core:net"
import "core:os"
import "core:strconv"
import "core:time"

Client :: struct {
	socket:    Communication,
	allocator: mem.Allocator,
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
	return {com = res._socket, arena = client.allocator}, nil
}
