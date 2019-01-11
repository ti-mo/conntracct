package udpecho

import (
	"log"
	"net"
	"strconv"
	"time"
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
func Dial(port uint16) MockUDP {

	dst, err := net.ResolveUDPAddr("udp", "localhost:"+strconv.Itoa(int(port)))
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
	b := make([]byte, 65507)

	go func() {
		for {
			// Wait for a control message.
			c, ok := <-ctrl
			if !ok {
				// Channel closed, stop goroutine.
				return
			}

			if c {
				// Write ping message to connection.
				n, err := conn.Write(ping)
				if err != nil || n != len(ping) {
					log.Fatalln("error writing ping to conn:", err)
				}

				// Set the read deadline to 20ms in the future.
				if err = conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
					log.Fatalln("error setting read deadline:", err)
				}

				// Expect a response from the server in case payload is 'ping'.
				n, _, err = conn.ReadFromUDP(b)
				if err != nil {
					log.Fatalln("error reading packet from conn:", err)
				}

				// Expect the response to be 'pong', halt when that's not the case.
				if string(b[:n]) != string(pong) {
					log.Fatalf("expected UDP response '%s', got '%s'", pong, b[:n])
				}
			} else {
				// Write nop message to connection, don't expect a response.
				n, err := conn.Write(nop)
				if err != nil || n != len(nop) {
					log.Fatalln("error writing nop to conn:", err)
				}
			}
		}
	}()

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
