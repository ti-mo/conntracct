package influxdb

import influx "github.com/influxdata/influxdb/client/v2"

// protoIntStr is a fast conversion of a protocol number into a string.
// Only the types known in nf_conntrack_tuple_common.h are included.
func protoIntStr(i uint8) string {
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

// newBatch writes a new InfluxDB client batch to the sink.
func (s *InfluxAcctSink) newBatch() {

	b, err := influx.NewBatchPoints(influx.BatchPointsConfig{
		Precision: "ns", // nanosecond precision timestamps
	})

	if err != nil {
		panic(err)
	}

	s.batch = b
}
