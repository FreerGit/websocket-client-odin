// //+private

package client

import "core:bytes"
import "core:log"
import "core:net"

// Websocket_Fragment_my :: struct {
// 	msg_type: Message_Type,
// 	final:    bool,
// 	payload:  []byte,
// }

Websocket_Fragment :: struct {
	data:     Websocket_Fragment_Data,
	final:    bool,
	mask:     bool,
	mask_key: [4]byte,
}

Websocket_Fragment_Data :: union {
	Continuation_Data,
	Text_Data,
	Binary_Data,
	Close_Data,
	Ping_Data,
	Pong_Data,
}

Message_Type :: enum u8 {
	Continuation_Data,
	Text_Data,
	Binary_Data,
	Close_Data,
	Ping_Data,
	Pong_Data,
}

Continuation_Data :: struct {
	payload: []byte,
}

Text_Data :: struct {
	payload: []byte,
}

Binary_Data :: struct {
	payload: []byte,
}

Close_Data :: struct {
	payload: []byte,
}

Ping_Data :: struct {
	payload: []byte,
}

Pong_Data :: struct {
	payload: []byte,
}

Websocket_Parse_Error :: union {
	Invalid_Opcode,
}

Invalid_Opcode :: struct {
	opcode: u8,
}

// to_message_type :: proc(byte: u8) -> Message_Type {
// 	switch byte {
// 	case 0:
// 		return .Continuation_Data
// 	case 1:
// 		return .Text_Data
// 	case 2:
// 		return .Binary_Data
// 	case 8:
// 		return .Close_Data
// 	case 9:
// 		return .Ping_Data
// 	case 10:
// 		return .Pong_Data
// 	}
// 	log.debug(byte)
// 	assert(false)
// 	return .Binary_Data
// }

// // remaining_data: []byte,
// // error: Websocket_Parse_Error,
// parse_frame :: proc(data: []byte) -> (frame: Websocket_Fragment_my, remaining: []byte, get_new: bool) {

// 	curr_byte := data[0]
// 	frame.final = ((curr_byte & 0x80) != 0)
// 	rsv1 := ((curr_byte & 0x40) != 0)
// 	rsv2 := ((curr_byte & 0x20) != 0)
// 	rsv3 := ((curr_byte & 0x10) != 0)
// 	log.debug(curr_byte)
// 	frame.msg_type = to_message_type(curr_byte & 0x0F)

// 	// TODO: add control frame fin validation here
// 	// TODO: add frame RSV validation here

// 	curr_byte = data[1]

// 	masked := ((curr_byte & 0x80) != 0)
// 	payload_length: u64 = u64(curr_byte) & 0x7F
// 	log.debug(payload_length)
// 	if payload_length > u64(len(data)) {
// 		return Websocket_Fragment_my{}, data, true
// 	}
// 	byte_count := 0

// 	i := 2
// 	if payload_length == 126 {
// 		payload_length_bytes := [2]byte{data[i], data[i + 1]}
// 		payload_length = u64(transmute(u16be)payload_length_bytes)
// 		i += 2
// 		byte_count = 2
// 	} else if payload_length == 127 {
// 		payload_length_bytes := [8]byte {
// 			data[i],
// 			data[i + 1],
// 			data[i + 2],
// 			data[i + 3],
// 			data[i + 4],
// 			data[i + 5],
// 			data[i + 6],
// 			data[i + 7],
// 		}
// 		payload_length = u64(transmute(u64be)payload_length_bytes)
// 		log.debugf("64 bit payload length: %d\n", payload_length)
// 		i += 8
// 		byte_count = 8
// 	}

// 	// log.debug(byte_count)
// 	// for byte_count -= 1; byte_count > 0; {
// 	// 	// curr_byte, _ = bytes.buffer_read_byte(&b)
// 	// 	curr_byte = data[i]
// 	// 	// log.debug("here")
// 	// 	payload_length |= u64((curr_byte & 0xFF) << (8 * u8(byte_count)))
// 	// 	byte_count -= 1
// 	// 	i += 1

// 	// }

// 	// TODO: add control frame payload length validation here

// 	mask_key: []byte = {0, 0, 0, 0}
// 	if masked {
// 		// for j: u8 = 0; j < payload_length; j += 1 {
// 		// data[i + int(j)] = data[i + int(j)] ~ mask_key[j % 4]
// 		mask_key = {data[i], data[i + 1], data[i + 2], data[i + 3]}
// 		i += 4
// 		// }
// 	}

// 	// TODO: add masked + maskingkey validation here

// 	frame.payload = data[i:i + int(payload_length)]
// 	remaining = data[i + int(payload_length):]

// 	if (masked) {
// 		for i := 0; i < len(frame.payload); i += 1 {
// 			frame.payload[i] ~= mask_key[i % 4]
// 		}
// 	}
// 	// log.debugf("%s", data[i + int(payload_length):])
// 	return frame, remaining, false

// 	// copy := data[:]
// 	// i: int
// 	// first_byte := data[0]
// 	// fragment.final = (first_byte & 128) == 128
// 	// log.debug(fragment)

// 	// opcode := first_byte & 0x0f
// 	// i += 1

// 	// second_byte := data[1]
// 	// log.debug(int(second_byte))
// 	// // log.debug(string(data))
// 	// mask := (second_byte & 0x80) != 0
// 	// payload_length: u64 = u64(second_byte) & 0x7f
// 	// i += 1
// 	// if payload_length == 126 {
// 	// 	payload_length_bytes := [2]byte{data[i], data[i + 1]}
// 	// 	payload_length = u64(transmute(u16be)payload_length_bytes)
// 	// 	i += 2
// 	// } else if payload_length == 127 {
// 	// 	payload_length_bytes := [8]byte {
// 	// 		data[i],
// 	// 		data[i + 1],
// 	// 		data[i + 2],
// 	// 		data[i + 3],
// 	// 		data[i + 4],
// 	// 		data[i + 5],
// 	// 		data[i + 6],
// 	// 		data[i + 7],
// 	// 	}
// 	// 	payload_length = u64(transmute(u64be)payload_length_bytes)
// 	// 	i += 8
// 	// }

// 	// if mask {
// 	// 	mask_key := data[i:i + 4]
// 	// 	i += 4
// 	// 	for j := u64(0); j < payload_length; j += 1 {
// 	// 		data[i + int(j)] = data[i + int(j)] ~ mask_key[j % 4]
// 	// 	}
// 	// }

// 	// payload := data[i:i + int(payload_length)]
// 	// remaining_data = data[i + int(payload_length):]
// 	// log.debug(string(payload))
// 	// log.debug(string(remaining_data))

// 	// switch opcode {
// 	// case 0x00:
// 	// 	fragment.data = Continuation_Data {
// 	// 		payload = payload,
// 	// 	}

// 	// 	return fragment, remaining_data, nil

// 	// case 0x01:
// 	// 	fragment.data = Text_Data {
// 	// 		payload = payload,
// 	// 	}

// 	// 	return fragment, remaining_data, nil

// 	// case 0x02:
// 	// 	fragment.data = Binary_Data {
// 	// 		payload = payload,
// 	// 	}

// 	// 	return fragment, remaining_data, nil

// 	// // control fragments
// 	// case 0x08:
// 	// 	fragment.data = Close_Data {
// 	// 		payload = payload,
// 	// 	}

// 	// 	return fragment, remaining_data, nil

// 	// case 0x09:
// 	// 	fragment.data = Ping_Data {
// 	// 		payload = payload,
// 	// 	}

// 	// 	return fragment, remaining_data, nil

// 	// case 0x0a:
// 	// 	fragment.data = Pong_Data {
// 	// 		payload = payload,
// 	// 	}

// 	// 	return fragment, remaining_data, nil

// 	// case:
// 	// 	// log.debug(string(copy))
// 	// 	return Websocket_Fragment{}, remaining_data, Invalid_Opcode{opcode = opcode}
// 	// }
// }

Serialize_Websocket_Fragment :: union {
	net.Network_Error,
	Buffer_Too_Small,
}

Buffer_Too_Small :: struct {
	required_size: int,
}

serialize_websocket_fragment :: proc(
	buffer: []byte,
	fragment: Websocket_Fragment,
) -> (
	serialized_data: []byte,
	error: Serialize_Websocket_Fragment,
) {
	i: int
	buffer[i] = 0
	if fragment.final {
		buffer[i] = buffer[i] | 0x80 // 0b1000_0000
	}

	// we have no ext/reserved bits support, so don't set them

	payload_length: u64
	payload_data: []byte
	switch t in fragment.data {
	case Continuation_Data:
		buffer[i] = buffer[i] & 0xf0
		payload_length = u64(len(t.payload))
		payload_data = t.payload
	case Text_Data:
		buffer[i] = buffer[i] | 0x01
		payload_length = u64(len(t.payload))
		payload_data = t.payload
	case Binary_Data:
		buffer[i] = buffer[i] | 0x02
		payload_length = u64(len(t.payload))
		payload_data = t.payload
	case Close_Data:
		buffer[i] = buffer[i] | 0x08
		payload_length = u64(len(t.payload))
		payload_data = t.payload
	case Ping_Data:
		buffer[i] = buffer[i] | 0x09
		payload_length = u64(len(t.payload))
		payload_data = t.payload
	case Pong_Data:
		buffer[i] = buffer[i] | 0x0a
		payload_length = u64(len(t.payload))
		payload_data = t.payload
	}
	i += 1

	if fragment.mask {
		buffer[i] = buffer[i] | 0x80 // 0b1000_0000
	}

	if payload_length > u64(len(buffer) - i) {
		return nil, Buffer_Too_Small{required_size = int(payload_length) + i}
	} else if payload_length > 65_535 {
		buffer[i] = 127
		i += 1

		payload_length_bytes: [8]byte = transmute([8]byte)u64be(payload_length)
		copy(buffer[i:], payload_length_bytes[:])
		i += 8
	} else if payload_length > 125 {
		buffer[i] = 126
		i += 1

		payload_length_bytes: [2]byte = transmute([2]byte)u16be(payload_length)
		copy(buffer[i:], payload_length_bytes[:])
		i += 2
	} else {
		buffer[i] = buffer[i] | byte(payload_length)
		i += 1
	}


	if fragment.mask {
		key := fragment.mask_key
		copy(buffer[i:], key[:])
		i += 4
	}

	// mask our payload data (assumes that it is not pre-masked)
	if fragment.mask {
		key := fragment.mask_key
		for j := u64(0); j < payload_length; j += 1 {
			payload_data[j] = payload_data[j] ~ key[j % 4]
		}
	}

	copy(buffer[i:], payload_data)
	i += int(payload_length)

	return buffer[:i], nil
}
