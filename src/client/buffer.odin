package client

import "core:log"
import "core:slice"

Buffer :: struct {
	i:       int,
	handled: int,
	data:    []byte,
}

buffer_pull :: proc(rb: ^Buffer, take: uint) -> (buf: []byte, err: ParseError) {
	if rb.i + int(take) > len(rb.data) {
		rb.i = rb.i - rb.handled
		return rb.data[rb.i:], IndexOutOfRange{}
	}
	buf = rb.data[rb.i:rb.i + int(take)]
	rb.i += int(take)
	return
}


buffer_unread_u16 :: #force_inline proc(rb: ^Buffer) {
	rb.i -= 2
}

buffer_pull_u8 :: proc(rb: ^Buffer) -> (buf: byte, err: ParseError) {
	// return  or_return, nil
	d := rb.data[rb.i]
	rb.i += 1
	rb.handled += 1
	return d, nil
}

buffer_pull_u16 :: proc(rb: ^Buffer) -> (buf: [2]byte, err: ParseError) {
	data := rb.data
	i := rb.i
	b := [2]byte{data[i], data[i + 1]}
	rb.i += 2
	rb.handled += 2
	return b, nil
}

buffer_pull_u32 :: proc(rb: ^Buffer) -> (buf: [4]byte, err: ParseError) {
	data := rb.data
	i := rb.i
	b := [4]byte{data[i], data[i + 1], data[i + 2], data[i + 3]}
	rb.i += 4
	rb.handled += 4
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
	rb.handled += 8
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

buffer_combine :: proc(uncomplete: ^Buffer, read: ^Buffer) {
	a := [][]byte{uncomplete.data, read.data}
	buf, _ := slice.concatenate(a)
	read.data = buf
	read.i = 0
}


import "core:testing"

@(test)
test_buffer_combine :: proc(t: ^testing.T) {
	uncomplete := Buffer{4, 4, []byte{103, 104, 105, 106, 107, 108, 109}}

	read := Buffer{6, 4, []byte{110, 111, 112, 113, 114, 115, 116, 117}}

	combined := Buffer {
		i = 0,
		data = []byte{103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117},
	}
	testing.log(t, read.data)
	testing.log(t, uncomplete.data)

	buffer_combine(&uncomplete, &read)
	testing.log(t, read.data)

	testing.expect(t, read.i == combined.i)
	is_same := true
	for _, i in combined.data {
		if combined.data[i] != read.data[i] {
			is_same = false
		}
	}
	testing.expect(t, is_same)
}
