package client

import "core:log"

Buffer :: struct {
	i:    int,
	data: []byte,
}


buffer_pull :: proc(rb: ^Buffer, take: uint) -> (buf: []byte, err: ParseError) {
	if (len(rb.data) - rb.i < int(take)) {
		log.error((len(rb.data)), rb.i, take)
		log.error(string(rb.data[rb.i - 6:]))
		return nil, EndOfPayload{}
	}
	buf = rb.data[rb.i:rb.i + int(take)]
	rb.i += int(take)
	return
}

buffer_pull_u8 :: proc(rb: ^Buffer) -> (buf: byte, err: ParseError) {
	// return  or_return, nil
	d := rb.data[rb.i]
	rb.i += 1
	return d, nil
}

buffer_pull_u16 :: proc(rb: ^Buffer) -> (buf: [2]byte, err: ParseError) {
	data := rb.data
	i := rb.i
	b := [2]byte{data[i], data[i + 1]}
	rb.i += 2
	return b, nil
}


buffer_pull_u32 :: proc(rb: ^Buffer) -> (buf: [4]byte, err: ParseError) {
	data := rb.data
	i := rb.i
	b := [4]byte{data[i], data[i + 1], data[i + 2], data[i + 3]}
	rb.i += 4
	return b, nil
}

buffer_pull_u64 :: proc(rb: ^Buffer) -> (buf: [8]byte, err: ParseError) {
	data := rb.data
	i := rb.i
	b := [8]byte {
		data[i],
		data[i + 1],
		data[i + 2],
		data[i + 3],
		data[i + 4],
		data[i + 5],
		data[i + 6],
		data[i + 7],
	}
	rb.i += 8
	return b, nil
}

buffer_mask_remaining :: proc(rb: ^Buffer, len: uint) -> (err: ParseError) {
	rb.i -= 4
	i := rb.i
	data := rb.data
	masking_key := buffer_pull_u32(rb) or_return
	for j := uint(0); j < len; j += 1 {
		data[i + int(j)] = data[i + int(j)] ~ masking_key[j % 4]
	}
	return nil
}
