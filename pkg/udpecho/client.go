package udpecho

import (
	"fmt"
	"log"
	"net"
)

var (
	ping = []byte("ping") // packet to send when expecting a response
	pong = []byte("pong") // expected response from ping packet
	nop  = []byte("nop")  // no-op packet to send when not expecting a response
)

// MockUDP holds a UDP socket to localhost
type MockUDP struct {
	conn *net.UDPConn
	ctrl chan bool
}

// Dial opens a UDP socket to the given port on localhost.
// Returns a new MockUDP.
// When host is an empty string, connects to 127.0.1.1 by default.
func Dial(host string, port uint16) MockUDP {

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

	ctrl := make(chan bool)

	go clientWorker(ctrl, conn)

	return MockUDP{
		conn: conn,
		ctrl: ctrl,
	}
}

// Close closes the MockUDPs control channel and connection,
// in that order.
func (m MockUDP) Close() {
	close(m.ctrl)
	_ = m.conn.Close()
}

// Ping generates num outgoing and expected return packets
// on the connection to localhost.
func (m MockUDP) Ping(num uint) {
	for i := 0; i < int(num); i++ {
		m.ctrl <- true
	}
}

// Nop generates num outgoing packets on the connection to localhost.
func (m MockUDP) Nop(num uint) {
	for i := 0; i < int(num); i++ {
		m.ctrl <- false
	}
}

// ClientAddr returns the client address of the MockUDP socket.
func (m MockUDP) ClientAddr() *net.UDPAddr {
	return m.conn.LocalAddr().(*net.UDPAddr)
}

// ClientPort returns the auto-generated client port of the connection.
func (m MockUDP) ClientPort() uint16 {
	return uint16(m.ClientAddr().Port)
}
