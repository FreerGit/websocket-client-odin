//+private

package client

import "core:bytes"
import "core:log"
import "core:net"

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
