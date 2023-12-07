package client


import "core:crypto"
import "core:encoding/base64"
import "core:fmt"
import "core:log"
import "core:math/rand"
import "core:net"
import "core:os"
import "core:time"

main :: proc() {
	argv := os.args

	// context.logger = log.create_console_logger()

	adress := "xxx://localhost:8000"

	key_bytes: [16]byte
	fmt.println(key_bytes)
	bytes_filled := rand.read(key_bytes[:])
	assert(bytes_filled == len(key_bytes))
	key := base64.encode(key_bytes[:])
	fmt.println(key)
	// host := domain.host_from_url(adress)
	// fmt.println(host)
}
