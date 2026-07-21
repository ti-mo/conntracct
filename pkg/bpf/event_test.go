package bpf

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashFlow(t *testing.T) {

	e := Event{
		SrcAddr: netip.MustParseAddr("1.2.3.4"),
		DstAddr: netip.MustParseAddr("5.6.7.8"),
		SrcPort: 1234,
		DstPort: 5678,
		Proto:   6,
		connPtr: 11111111111111111111,
	}

	assert.Equal(t, uint32(0x4bbb6733), e.hashFlow())
}
