package udpecho

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

var (
	ping = []byte("ping") // packet to send when expecting a response
	pong = []byte("pong") // expected response from ping packet
	nop  = []byte("nop")  // no-op packet to send when not expecting a response
)

// MockUDPClient holds a local UDP socket.
type MockUDPClient struct {
	mu   sync.RWMutex
	conn *net.UDPConn
	ctrl chan bool
}

// Dial opens a UDP socket to the given port on localhost.
// Returns a new MockUDPClient.
// When host is an empty string, connects to 127.0.1.1 by default.
func Dial(host string, port uint16) *MockUDPClient {

	if host == "" {
		host = "127.0.1.1"
	}

	dst, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		log.Fatalln("error resolving UDP address:", err)
	}

	// Dial instead of ListenPacket so the connection is locked to
	// the specified destination address. Calls `connect()` with SOCK_DGRAM.
	conn, err := net.DialUDP("udp4", nil, dst)
	if err != nil {
		log.Fatalln("error opening client listener:", err)
	}

	m := MockUDPClient{
		conn: conn,
		ctrl: make(chan bool),
	}

	go m.worker()

	return &m
}

// Close closes the MockUDPClients control channel and connection,
// in that order.
func (m *MockUDPClient) Close() {

	// Wait for a write lock to avoid closing the socket during an r/w operation.
	m.mu.Lock()
	defer m.mu.Unlock()

	close(m.ctrl)
	_ = m.conn.Close()
}

// Ping generates num outgoing and expected return packets
// on the connection to localhost.
func (m *MockUDPClient) Ping(num uint) {
	for i := 0; i < int(num); i++ {
		m.ctrl <- true
	}
}

// Nop generates num outgoing packets on the connection to localhost.
func (m *MockUDPClient) Nop(num uint) {
	for i := 0; i < int(num); i++ {
		m.ctrl <- false
	}
}

// ClientAddr returns the client address of the MockUDPClient socket.
func (m *MockUDPClient) ClientAddr() *net.UDPAddr {
	return m.conn.LocalAddr().(*net.UDPAddr)
}

// ClientPort returns the auto-generated client port of the connection.
func (m *MockUDPClient) ClientPort() uint16 {
	return uint16(m.ClientAddr().Port)
}

func (m *MockUDPClient) worker() {

	b := make([]byte, 65507)

	for {
		// Wait for a control message.
		c, ok := <-m.ctrl
		if !ok {
			// Channel closed, stop goroutine.
			return
		}

		// Obtain lock to the client.
		m.mu.RLock()

		if c {

			// Write ping message to connection.
			n, err := m.conn.Write(ping)
			if err != nil || n != len(ping) {
				log.Fatalln("error writing ping to conn:", err)
			}

			// Set the read deadline to 20ms in the future.
			if err = m.conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
				log.Fatalln("error setting read deadline:", err)
			}

			// Expect a response from the server in case payload is 'ping'.
			n, _, err = m.conn.ReadFromUDP(b)
			if err != nil {
				log.Fatalln("error reading packet from conn:", err)
			}

			// Expect the response to be 'pong', halt when that's not the case.
			if string(b[:n]) != string(pong) {
				log.Fatalf("expected UDP response '%s', got '%s'", pong, b[:n])
			}
		} else {
			// Write nop message to connection, don't expect a response.
			n, err := m.conn.Write(nop)
			if err != nil || n != len(nop) {
				log.Fatalln("error writing nop to conn:", err)
			}
		}

		// Release client's read lock.
		m.mu.RUnlock()
	}
}
