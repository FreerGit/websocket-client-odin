package domain

import "core:net"

URL :: struct {
	raw:     string, // All other fields are views/slices into this string.
	scheme:  string,
	host:    string,
	path:    string,
	queries: map[string]string,
}

url_parse :: proc(raw: string, allocator := context.allocator) -> URL {
	url: URL
	url.raw = raw
	url.scheme, url.host, url.path, url.queries = net.split_url(raw, allocator)
	return url
}

url_string :: proc(url: URL, allocator := context.allocator) -> string {
	return net.join_url(url.scheme, url.host, url.path, url.queries, allocator)
}

parse_endpoint :: proc(target: string) -> (url: URL, endpoint: net.Endpoint, err: net.Network_Error) {
	url = url_parse(target)
	host_or_endpoint := net.parse_hostname_or_endpoint(url.host) or_return

	switch t in host_or_endpoint {
	case net.Endpoint:
		endpoint = t
		return
	case net.Host:
		ep4, ep6 := net.resolve(t.hostname) or_return
		endpoint = ep4 if ep4.address != nil else ep6

		endpoint.port = t.port
		if endpoint.port == 0 {
			endpoint.port = url.scheme == "https" || url.scheme == "wss" ? 443 : 80
		}
		return
	case:
		unreachable()
	}
}
