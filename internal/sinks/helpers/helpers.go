package helpers

// ProtoIntStr is a fast conversion of a protocol number into a string.
// Only the types known in nf_conntrack_tuple_common.h are included.
func ProtoIntStr(i uint8) string {
	switch i {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 33:
		return "dccp"
	case 47:
		return "gre"
	case 132:
		return "sctp"
	}

	return "unknown"
}
