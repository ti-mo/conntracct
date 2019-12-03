package udpecho

import (
	"fmt"
	"log"
	"net"
)

// ListenAndEcho starts a UDP listener that replies 'pong'
// in response to a request packet containing 'ping'.
// When host is an empty string, listens on 127.0.1.1 by default.
func ListenAndEcho(host string, port uint16) net.PacketConn {

	if host == "" {
		host = "127.0.1.1"
	}

	l, err := net.ListenPacket("udp4", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		log.Fatalln("error opening UDP listener:", err)
	}

	go serverWorker(l)

	return l
}
