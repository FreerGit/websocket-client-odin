package client

import "core:bytes"
import "core:log"
import "core:os"

ParseError :: union {
	NoHeader,
	NotSupportFrag,
	ServerMasked,
	BufferSizeUnexpected,
	IndexOutOfRange,
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

IndexOutOfRange :: struct {}

InvalidOpcode :: struct {
	opcode: u8,
}

FrameNotComplete :: struct {
	rest: []byte,
	i:    int,
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

parse_header :: proc(buffer: ^Buffer, frame: ^Frame) -> (err: ParseError) {
	if (len(buffer.data[buffer.i:]) < 2) {
		return NoHeader{}
	}
	head := buffer_pull_u8(buffer) or_return
	frame.fin = (head & 0x80) == 0x80
	frame.opcode = get_opcode(head & 0x0F) or_return

	length := buffer_pull_u8(buffer) or_return
	frame.mask = length & 0x80 == 0x80
	frame.payload_len = uint(length & 0x7F)

	if (!frame.fin && len(buffer.data) < int(frame.payload_len)) {
		buffer_unread_u16(buffer)
		return FrameNotComplete{rest = buffer.data, i = len(buffer.data)}
	}
	return nil
}

parse_payload_length :: proc(buffer: ^Buffer, frame: ^Frame) -> (err: ParseError) {

	switch frame.payload_len {
	case 126:
		if (len(buffer.data) < 4) {
			return BufferSizeUnexpected{"Expected reader size < 4"}
		}
		frame.payload_len = uint(transmute(u16be)(buffer_pull_u16(buffer) or_return))
	case 127:
		if (len(buffer.data) < 10) {
			return BufferSizeUnexpected{"Expected reader size < 10"}
		}
		frame.payload_len = uint(transmute(u64be)(buffer_pull_u64(buffer) or_return))
	// TODO: what if too large?
	case:
		break
	}
	return nil
}

parse_message :: proc(buffer: ^Buffer, frame: ^Frame) -> (err: ParseError) {
	buf, index_error := buffer_pull(buffer, frame.payload_len)
	buffer.handled = 0
	if index_error != nil {

		return FrameNotComplete{rest = buf, i = len(buf)}
	}
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

parse_frame :: proc(read: ^Buffer) -> (frame: Frame, err: ParseError) {
	if (read.i == len(read.data)) {
		return Frame{}, EOF{}
	}

	parse_header(read, &frame) or_return
	parse_payload_length(read, &frame) or_return
	p_err := parse_message(read, &frame)
	return frame, p_err
}
