package client

import "core:bytes"
import "core:log"
import "core:os"

ParseError :: union {
	NoHeader,
	NotSupportFrag,
	ServerMasked,
	BufferSizeUnexpected,
	// Not necesarily an error, means that the message was cut off and we need to wait for more data to be read for socket!
	EndOfPayload,
}

NoHeader :: struct {}

NotSupportFrag :: struct {
	payload: string,
}
ServerMasked :: struct {}

BufferSizeUnexpected :: struct {
	payload: string,
}

EndOfPayload :: struct {}

Opcode :: enum u8 {
	Continue = 0x0,
	Text     = 0x1,
	Binary   = 0x2,
	Close    = 0x8,
	Ping     = 0x9,
	Pong     = 0xA,
}

parse_header :: proc(client: ^Client) -> (err: ParseError) {
	rb := &client.r_buffer
	frame := &client.frame

	// log.debugf("reader size: %i, position: %i", len(rb.data), rb.i)
	if (len(rb.data[rb.i:]) < 2) {
		return NoHeader{}
	}

	head := buffer_pull_u8(rb) or_return

	fin := (head & 0x80) == 0x80
	// log.debug(fin)
	// log.debug(head)
	// log.debug(head & 0x80)
	// log.debug(string(rb.data[rb.i:]))
	frame.opcode = (Opcode)(head & 0x0F)
	// log.debug(client.frame.opcode)


	if (!fin || frame.opcode == .Continue) {
		// return NotSupportFrag{"Not a support fragment"}
	}

	len := buffer_pull_u8(rb) or_return

	// masked := ((curr_byte & 0x80) != 0)
	frame.mask = len & 0x80 == 0x80

	frame.payload_len = uint(len & 0x7F)

	return nil
}

parse_payload_length :: proc(client: ^Client) -> (err: ParseError) {
	rb := &client.r_buffer
	frame := &client.frame

	switch frame.payload_len {
	case 126:
		if (len(rb.data) < 4) {
			return BufferSizeUnexpected{"Expected reader size < 4"}
		}
		frame.payload_len = uint(transmute(u16be)(buffer_pull_u16(rb) or_return))
	case 127:
		if (len(rb.data) < 10) {
			return BufferSizeUnexpected{"Expected reader size < 10"}
		}
		frame.payload_len = uint(transmute(u64be)(buffer_pull_u64(rb) or_return))
	// TODO: what if too large?
	case:
		break
	}
	return nil
}

parse_message :: proc(client: ^Client) -> (err: ParseError) {
	rb := &client.r_buffer
	frame := &client.frame

	if (len(rb.data) < int(frame.payload_len)) {
		log.error(len(rb.data), frame.payload_len)
		return BufferSizeUnexpected{"buffer is smaller than payload_len"}
	}

	buf := buffer_pull(rb, frame.payload_len) or_return
	// log.debug(string(rb.data[rb.i:]))

	frame.payload = buf
	if frame.mask {
		log.error("IS MASKED?")
		// os.exit(1)
		buffer_mask_remaining(rb, frame.payload_len) or_return

		// log.debug(mask_key)
		// log.debug(frame.payload_len)
		// os.exit(1)


	}

	return nil
}

parse_frame :: proc(client: ^Client) -> (remaining: []byte, err: ParseError) {
	if (client.r_buffer.i == len(client.r_buffer.data) - 1) {
		return nil, EndOfPayload{}
	}

	parse_header(client) or_return
	parse_payload_length(client) or_return
	p_err := parse_message(client)
	#partial switch v in p_err {
	case EndOfPayload:
		// go left by 2 bytes, need the headers!
		return client.r_buffer.data[client.r_buffer.i - 2:], v
	case:
		return nil, v
	}
	return nil, nil
}


// read :: proc(client: ^Client) -> 
