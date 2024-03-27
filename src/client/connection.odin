package client

import openssl "../../deps/openssl"
import "core:c"
import "core:encoding/endian"
import "core:math/rand"
import "core:mem"
import "core:reflect"


@(private)
r := rand.create(18)


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
connection_send :: proc(conn: ^Connection, payload: string) -> Error {
	return send_raw(conn, .text, payload, false)


}

connection_ping :: proc(conn: ^Connection) -> Error {
	return send_raw(conn, .ping, {}, false)
}

@(private)
send_raw :: proc(conn: ^Connection, op: Opcode, payload: string, nonzero_mask: bool) -> Error {
	context.allocator = conn.arena
	max_size: uint = max_frame_header_size + len(payload)

	if len(conn.write_buffer) < int(max_size) {
		conn.write_buffer = mem.resize_bytes(conn.write_buffer, int(max_size)) or_return
	}

	msg := conn.write_buffer // ZII
	msg[0] |= fin_bit
	msg[0] |= u8(op)

	msg[1] |= mask_bit

	next: uint
	actual_size: uint
	if len(payload) <= 125 {
		sm_length: u8 = cast(u8)(len(payload))
		msg[1] |= sm_length
		next = 2
		actual_size = max_size - 8
	} else if len(payload) < 65536 {
		msg[1] |= 126
		mid_length: u16 = cast(u16)(len(payload))
		endian.put_u16(msg[2:4], .Big, mid_length)
		next = 4
		actual_size = max_size - 6
	} else {
		msg[1] |= 127
		big_length: u64 = cast(u64)(len(payload))
		endian.put_u64(msg[2:10], .Big, big_length)
		next = 10
		actual_size = max_size
	}

	if nonzero_mask {
		panic("nonzero_mask unimplemented")

	} else {
		copy_slice(msg[next:next + 4], []byte{0, 0, 0, 0})
	}

	copy_slice(msg[next + 4:], transmute([]u8)payload)

	if nonzero_mask {
		panic("nonzero_mask unimplemented")
	} else {
		// zero mask, no effect
	}

	to_send := msg[0:actual_size]
	bytes_written := openssl.SSL_write(conn.com.ssl, raw_data(to_send), i32(len(to_send)))
	// TODO: create error enum for openssl lib
	return Connection_Error.Write_Error if bytes_written <= 0 else nil
}

@(private)
mask_bytes :: proc(mask: ^[4]byte, bytes: []byte) {
	for b, i in bytes {
		bytes[i] = b ~ mask[i % 4]
	}
}

connection_recv :: proc(conn: ^Connection) -> (str: string, err: Error) {
	for {
		header := receive_header(conn) or_return
		switch header.op {
		case .continuation:
			panic("unimplemented")
		case .close:
			return "", Connection_Error.Closed
		case .ping, .pong:
			send_raw(conn, .pong, {}, false) or_return
			// @TODO 
			continue
		case .text, .binary:
			payload, _ := mem.alloc_bytes_non_zeroed(cast(int)header.payload_len, allocator = conn.arena)
			n: uint = 0
			for n < header.payload_len {
				more := openssl.SSL_read(conn.com.ssl, raw_data(payload[n:]), i32(len(payload)))
				if more < 1 {
					panic("cant read payload?")
				}
				n = n + uint(more)
			}

			if header.has_mask {
				mask_bytes(&header.mask, payload)
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
	payload_len: uint,
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
	if (r < 2) {
		return {}, Connection_Error.Invalid_Frame
	}

	fin: bool = (tmp[0] & fin_bit) != 0
	if !fin {
		return {}, Connection_Error.Protocol_Not_Followed
	}

	if tmp[0] & rsv1_bit != 0 || tmp[0] & rsv2_bit != 0 || tmp[0] & rsv3_bit != 0 {
		return {}, Connection_Error.Protocol_Not_Followed
	}

	op := tmp[0] & 0x0f
	has_mask: bool = tmp[1] & mask_bit != 0

	payload_len: uint = cast(uint)tmp[1] & payload_len_bits
	if payload_len == 126 {
		tmp = conn.read_buffer[0:2]
		n := openssl.SSL_read(conn.com.ssl, raw_data(tmp), c.int(len(tmp)))
		if n < 2 {
			return {}, Connection_Error.Invalid_Frame
		}

		payload_len_u16 := endian.get_u16(tmp[:2], .Big) or_else panic("get_u16")
		payload_len = cast(uint)payload_len_u16

	} else if payload_len == 127 {
		tmp = conn.read_buffer[0:8]
		n := openssl.SSL_read(conn.com.ssl, raw_data(tmp), c.int(len(tmp)))
		if n < 8 {
			return {}, Connection_Error.Invalid_Frame
		}

		payload_len_u64 := endian.get_u64(tmp[:8], .Big) or_else panic("get_u64")
		payload_len = cast(uint)payload_len_u64
	}

	mask: [4]u8
	if has_mask {
		n := openssl.SSL_read(conn.com.ssl, raw_data(&mask), c.int(len(mask)))
		if (n < 1) {
			return {}, Connection_Error.Invalid_Frame
		}
	}

	return Header{op = cast(Opcode)op, payload_len = payload_len, has_mask = has_mask, mask = mask}, nil

}
