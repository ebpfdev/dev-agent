package maps

import (
	"fmt"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/util"
)

type DisplayFormat = string

const (
	DisplayFormatHex    DisplayFormat = "hex"
	DisplayFormatString DisplayFormat = "string"
	DisplayFormatNumber DisplayFormat = "number"
)

func FormatBytes(format DisplayFormat, value []byte) string {
	switch format {
	case DisplayFormatString:
		// drop trailing zeros
		for i := len(value) - 1; i >= 0; i-- {
			if value[i] == 0 {
				value = value[:i]
			} else {
				break
			}
		}
		return string(value)
	case DisplayFormatHex:
		return fmt.Sprintf("%x", value)
	case DisplayFormatNumber:
		if len(value) <= 8 {
			buf := make([]byte, 8)
			copy(buf, value)
			return fmt.Sprintf("%d", int64(util.GetEndian().Uint64(buf)))
		}
		return fmt.Sprintf("%x", value)
	default:
		return fmt.Sprintf("%x", value)
	}
}
