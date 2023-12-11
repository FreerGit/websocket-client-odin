package client

import openssl "../../deps/odin-http/openssl"
import "../domain"

import "core:bufio"


Client :: struct {
	socket:   Communication,
	frame:    Frame,
	r_buffer: Buffer,
	// w_buffer: bufio.Writer,
}

Frame :: struct {
	opcode:      Opcode,
	payload_len: uint,
	payload:     []byte,
	mask:        bool,
	mask_key:    [4]byte,
}
