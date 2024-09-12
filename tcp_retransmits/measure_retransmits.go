package main

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"golang.org/x/sys/unix"
)

const (
	_exampleUrl = "https://news.ycombinator.com/"
)

// was the http request slow because of saturation of the network (we see tcp retransmits)
// or the application on the server side was slow
func main() {
	var conn net.Conn

	transport := http.DefaultTransport.(*http.Transport).Clone()

	// capture the conn to a local variable so we can get access to the underlying socket
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := net.Dial(network, addr)
		if err == nil {
			conn = c
		}
		return c, err
	}

	tcpRetransmitMeasuringClient := &http.Client{
		Transport: transport,
	}
	_, err := tcpRetransmitMeasuringClient.Get(_exampleUrl)
	if err != nil {
		panic(err)
	}

	// if it's http1.1 or http2 then we can get the tcp conn
	// otherwise there are probably some quic specific measurements that can be used instead
	tcpConn := conn.(*net.TCPConn)

	// we then need to coerce to a "syscallConn" so we can use getsockopt on it
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		panic(err)
	}

	raw.Control(func(fd uintptr) {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.SOL_TCP, unix.TCP_INFO)
		if err != nil {
			panic(err)
		}
		fmt.Printf("TCP Retransmits: %d\n", info.Retransmits)
		fmt.Printf("TCP Retrans: %d\n", info.Retrans)
		fmt.Printf("TCP Total_retrans: %d\n", info.Total_retrans)
		fmt.Printf("TCP Bytes_retrans: %d\n", info.Bytes_retrans)
	})
}
