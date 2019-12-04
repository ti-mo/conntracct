package udpecho

import (
	"fmt"
	"log"
	"net"
	"sync"
)

// MockUDPServer holds a mock UDP server.
type MockUDPServer struct {
	mu   sync.RWMutex
	conn net.PacketConn
}

// ListenAndEcho starts a UDP listener that replies 'pong'
// in response to a request packet containing 'ping'.
// When host is an empty string, listens on 127.0.1.1 by default.
func ListenAndEcho(host string, port uint16) *MockUDPServer {

	if host == "" {
		host = "127.0.1.1"
	}

	l, err := net.ListenPacket("udp4", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		log.Fatalln("error opening UDP listener:", err)
	}

	s := MockUDPServer{
		conn: l,
	}

	go s.worker()

	return &s
}

func (s *MockUDPServer) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.conn.Close()
}

func (s *MockUDPServer) worker() {

	b := make([]byte, 65507)

	for {
		n, addr, err := s.conn.ReadFrom(b)
		if err != nil {
			// Stop goroutine if socket is closed.
			return
		}

		// Reply 'pong' to the sender when payload is 'ping'.
		if string(b[:n]) == string(ping) {

			s.mu.RLock()

			_, err = s.conn.WriteTo(pong, addr)
			if err != nil {
				log.Fatalln("error echoing message to socket:", err)
			}

			s.mu.RUnlock()
		}
	}

}
