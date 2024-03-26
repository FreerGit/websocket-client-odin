package client

import openssl "../../deps/openssl"
import "core:c"
import "core:encoding/endian"
import "core:fmt"
import "core:mem"
import "core:reflect"


Connection_Error :: enum {
	Closed,
	Invalid_Frame,
	Write_Error,
	Protocol_Not_Followed,
	Invalid_URL,
}

Connection :: struct {
	com:          SSL_Communication,
	arena:        mem.Allocator,
	read_buffer:  [8]byte,
	write_buffer: []byte,
}


// TODO send_raw
connection_send :: proc(conn: ^Connection, content: string) -> Error {

	bytes_written := openssl.SSL_write(conn.com.ssl, raw_data(content), i32(len(content)))
	// TODO: create error enum for openssl lib
	return Connection_Error.Write_Error if bytes_written <= 0 else nil

}

connection_ping :: proc(conn: ^Connection) -> Error {
	return send_raw(conn, .ping, {}, false)
}

@(private)
send_raw :: proc(conn: ^Connection, op: Opcode, payload: string, nonzero_mask: bool) -> Error {
	context.allocator = conn.arena
	max_size := max_frame_header_size + len(payload)

	if len(conn.write_buffer) < max_size {
		conn.write_buffer = mem.resize()
	}
}


connection_recv :: proc(conn: ^Connection) -> (str: string, err: Error) {
	for {
		header := receive_header(conn) or_return
		fmt.println(header)
		switch header.op {
		case .continuation:
			panic("unimplemented")
		case .close:
			return "", Connection_Error.Closed
		case .ping, .pong:
			fmt.println(header.op)
			// @TODO 
			continue
		case .text, .binary:
			payload, _ := mem.alloc_bytes_non_zeroed(cast(int)header.payload_len, allocator = conn.arena)
			n: uintptr = 0
			for n < header.payload_len {
				more := openssl.SSL_write(conn.com.ssl, raw_data(payload[n:]), i32(len(payload)))
				if more < 1 {
					panic("cant read payload?")
				}
				n = n + uintptr(more)
			}

			// @TODO mask
			return string(payload), nil
		}

	}
}

Opcode :: enum (byte) {
	continuation = 0x0,
	text = 0x1,
	binary = 0x2,
	close = 0x8,
	ping = 0x9,
	pong = 0xa,
	_,
}

Header :: struct {
	op:          Opcode,
	payload_len: uintptr,
	has_mask:    bool,
	mask:        [4]byte,
}

@(private = "file")
max_frame_header_size :: 2 + 8 + 4 // fixed header + length + mask
@(private = "file")
mask_bit :: 1 << 7 // frame header byte 1 bits from section 5.2 of RFC 6455
@(private = "file")
payload_len_bits :: 0x7f
// frame header byte 0 bits from section 5.2 of RFC 6455
@(private = "file")
fin_bit :: 1 << 7
@(private = "file")
rsv1_bit :: 1 << 6
@(private = "file")
rsv2_bit :: 1 << 5
@(private = "file")
rsv3_bit :: 1 << 4

@(private)
receive_header :: proc(conn: ^Connection) -> (h: Header, err: Error) {
	tmp: []byte = conn.read_buffer[0:2]
	r := openssl.SSL_read(conn.com.ssl, raw_data(tmp), c.int(len(tmp)))
	fmt.println(tmp)
	if (r < 2) {
		return {}, Connection_Error.Invalid_Frame
	}

	fmt.println(tmp[0] & fin_bit)
	fin: bool = (tmp[0] & fin_bit) != 0
	if !fin {
		fmt.println("has ")
		return {}, Connection_Error.Protocol_Not_Followed
	}

	if tmp[0] & rsv1_bit != 0 || tmp[0] & rsv2_bit != 0 || tmp[0] & rsv3_bit != 0 {
		return {}, Connection_Error.Protocol_Not_Followed
	}

	op := tmp[0] & 0x0f
	has_mask: bool = tmp[1] & mask_bit != 0

	payload_len: uintptr = cast(uintptr)tmp[0] & payload_len_bits
	if payload_len == 126 {
		tmp = conn.read_buffer[0:2]
		n := openssl.SSL_read(conn.com.ssl, raw_data(tmp), c.int(len(tmp)))
		if n < 2 {
			return {}, Connection_Error.Invalid_Frame
		}

		payload_len_u16 := endian.get_u16(tmp[:2], .Big) or_else panic("get_u16")
		payload_len = cast(uintptr)payload_len_u16

	} else if payload_len == 127 {
		tmp = conn.read_buffer[0:8]
		n := openssl.SSL_read(conn.com.ssl, raw_data(tmp), c.int(len(tmp)))
		if n < 8 {
			return {}, Connection_Error.Invalid_Frame
		}

		payload_len_u64 := endian.get_u64(tmp[:8], .Big) or_else panic("get_u64")
		payload_len = cast(uintptr)payload_len_u64
	}

	mask: [4]u8 = {}
	if has_mask {
		n := openssl.SSL_read(conn.com.ssl, raw_data(&mask), c.int(len(mask)))
		if (n < 1) {
			return {}, Connection_Error.Invalid_Frame
		}
	}

	return Header{op = cast(Opcode)op, payload_len = payload_len, has_mask = has_mask, mask = mask}, nil

}
