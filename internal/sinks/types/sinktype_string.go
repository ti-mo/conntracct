// Code generated by "stringer -type=SinkType"; DO NOT EDIT.

package types

import "strconv"

const _SinkType_name = "StdOutStdErrInfluxUDPInfluxHTTPElastic"

var _SinkType_index = [...]uint8{0, 6, 12, 21, 31, 38}

func (i SinkType) String() string {
	if i >= SinkType(len(_SinkType_index)-1) {
		return "SinkType(" + strconv.FormatInt(int64(i), 10) + ")"
	}
	return _SinkType_name[_SinkType_index[i]:_SinkType_index[i+1]]
}
