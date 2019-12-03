package udpecho

import (
	"log"
	"net"
	"time"
)

func serverWorker(conn net.PacketConn) {

	b := make([]byte, 65507)

	for {
		n, addr, err := conn.ReadFrom(b)
		if err != nil {
			// Stop goroutine if socket is closed.
			return
		}

		// Reply 'pong' to the sender when payload is 'ping'.
		if string(b[:n]) == string(ping) {
			_, err = conn.WriteTo(pong, addr)
			if err != nil {
				log.Fatalln("error echoing message to socket:", err)
			}
		}
	}

}

func clientWorker(ctrl chan bool, conn *net.UDPConn) {

	b := make([]byte, 65507)

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
}
