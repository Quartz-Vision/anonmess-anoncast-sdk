package utils

import "encoding/binary"

func BytesToInt64(src []byte) (val int64, sizeRead int) {
	return int64(binary.BigEndian.Uint64(src[:INT_MAX_SIZE])), INT_MAX_SIZE
}

func Int64ToBytes(val int64) (res []byte) {
	return binary.BigEndian.AppendUint64([]byte{}, uint64(val))
}
