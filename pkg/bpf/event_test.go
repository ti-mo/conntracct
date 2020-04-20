package bpf

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashFlow(t *testing.T) {

	e := Event{
		SrcAddr: net.ParseIP("1.2.3.4"),
		DstAddr: net.ParseIP("5.6.7.8"),
		SrcPort: 1234,
		DstPort: 5678,
		Proto:   6,
		connPtr: 11111111111111111111,
	}

	assert.Equal(t, uint32(0x97c684), e.hashFlow())
}
