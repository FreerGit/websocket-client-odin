package domain

import "core:fmt"
import "core:strings"
import "core:testing"


host_from_url :: proc(url: string) -> string {
	url := url
	protocol_pos := strings.index(url, "://")

	if protocol_pos == -1 {
		protocol_pos = -3
	}

	rest := url[protocol_pos + 3:]

	slash_pos := strings.index(rest, "/")

	if slash_pos == -1 {
		return rest
	}

	return rest[:slash_pos]
}

@(test, private = "package")
test_host_from_url :: proc(t: ^testing.T) {
	cases := map[string]string {
		"https://google.com"                 = "google.com",
		"http://google.com/"                 = "google.com",
		"http://google.com"                  = "google.com",
		"http://google.com:8080"             = "google.com:8080",
		"http://google.com:8080/hello"       = "google.com:8080",
		"http://google.com:8080/hello/world" = "google.com:8080",
		"google.com"                         = "google.com",
		"google.com:8080"                    = "google.com:8080",
		"google.com/hello"                   = "google.com",
		"127.0.0.1:4200/ws"                  = "127.0.0.1:4200",
	}
	for input, expected in cases {
		host := host_from_url(input)
		testing.expect_value(t, host, expected)
	}
}
