package client

import "core:bytes"
import "core:log"
import "core:os"

ParseError :: union {
	NoHeader,
	NotSupportFrag,
	ServerMasked,
	BufferSizeUnexpected,
	InvalidOpcode,
	// Not necessarily an error, means that the message was cut off and we need to wait for more data to be read for socket!
	FrameNotComplete,
	// Not necessarily and error, signal to stop parsing and read more data.
	EOF,
}

NoHeader :: struct {}

NotSupportFrag :: struct {
	payload: string,
}
ServerMasked :: struct {}

BufferSizeUnexpected :: struct {
	payload: string,
}

InvalidOpcode :: struct {
	opcode: u8,
}

FrameNotComplete :: struct {
	rest: []byte,
}

EOF :: struct {}

Opcode :: enum u8 {
	Continue,
	Text,
	Binary,
	Close,
	Ping,
	Pong,
}

get_opcode :: proc(byte: u8) -> (opcode: Opcode, err: ParseError) {
	switch byte {
	case 0x1:
		return .Text, nil
	case 0x0:
		return .Continue, nil
	case 0x2:
		return .Binary, nil
	case 0x8:
		return .Close, nil
	case 0x9:
		return .Ping, nil
	case 0xA:
		return .Pong, nil
	case:
		return nil, InvalidOpcode{byte}
	}
}

parse_header :: proc(client: ^Client) -> (err: ParseError) {
	rb := &client.r_buffer
	frame := &client.frame

	// log.debugf("reader size: %i, position: %i", len(rb.data), rb.i)
	if (len(rb.data[rb.i:]) < 2) {
		return NoHeader{}
	}

	// log.debug(string(rb.data[rb.i:rb.i + 10]))
	head := buffer_pull_u8(rb) or_return

	frame.fin = (head & 0x80) == 0x80
	// log.debug(fin)
	// log.debug(head)
	// log.debug(head & 0x80)
	// log.debug(string(rb.data[rb.i:]))
	frame.opcode = get_opcode(head & 0x0F) or_return

	log.debug(client.frame.fin)
	log.debug(client.frame.opcode)


	length := buffer_pull_u8(rb) or_return

	// masked := ((curr_byte & 0x80) != 0)
	frame.mask = length & 0x80 == 0x80

	frame.payload_len = uint(length & 0x7F)

	if (!frame.fin && len(rb.data) < int(frame.payload_len)) {
		log.debug("LFDSKFJLSD:LSF")
		// frame.payload = {head, len}
		return(
			FrameNotComplete {
				rest = buffer_pull_frame(rb, frame.payload_len) or_return,
			} 
		)
	}
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

	// if (len(rb.data) < int(frame.payload_len)) {
	// 	log.error(len(rb.data), frame.payload_len)
	// 	return FrameNotComplete{rest = buffer_pull_frame(rb, frame.payload_len) or_return}
	// }

	buf := buffer_pull(rb, frame.payload_len) or_return

	frame.payload = buf
	// log.debug(string(rb.data[rb.i:]))

	// if frame.mask {
	// 	log.error("IS MASKED?")
	// 	// os.exit(1)
	// 	buffer_mask_remaining(rb, frame.payload_len) or_return

	// 	// log.debug(mask_key)
	// 	// log.debug(frame.payload_len)
	// 	// os.exit(1)


	// }

	return nil
}

parse_frame :: proc(read: ^Buffer, uncomplete: ^Buffer) -> (frame: Frame, err: ParseError) {
	// log.debug(read.i, len(read.data))
	if (read.i == len(read.data)) {
		return Frame{}, EOF{}
	} 
	if len(uncomplete.data) != 0 {
		buffer_combine(uncomplete, read)
	}
	// log.debug(string(client.r_buffer.data[client.r_buffer.i:]))
	parse_header(read, uncomplete) or_return
	parse_payload_length(client) or_return
	p_err := parse_message(client)
	#partial switch v in p_err {
	// case EndOfPayload:
	// 	// go left by 2 bytes, need the headers!
	// 	return client.r_buffer.data[client.r_buffer.i:], v
	case:
		return false, v
	}
	return false, nil
}

cleanup_after_parsing :: proc(client: ^Client) {
	client.frame = {}
	client.r_buffer = {}
}
// read :: proc(client: ^Client) -> 
