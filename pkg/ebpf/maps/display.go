package maps

import (
	"encoding/hex"
	"fmt"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/util"
	"strconv"
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

func RestoreBytes(format DisplayFormat, value string, expectedSize uint32) ([]byte, error) {
	if expectedSize == 0 {
		return nil, nil
	}

	switch format {
	case DisplayFormatString:
		if len(value) > int(expectedSize) {
			return nil, fmt.Errorf("string is too long (%d bytes vs %d expected)", len(value), expectedSize)
		}
		result := make([]byte, expectedSize)
		copy(result, value)
		return result, nil
	case DisplayFormatHex:
		if len(value)%2 != 0 {
			return nil, fmt.Errorf("hex data is not even")
		}
		if len(value) > int(expectedSize)*2 {
			return nil, fmt.Errorf("hex data is too long (%d bytes vs %d expected)", len(value)/2, expectedSize)
		}
		result := make([]byte, expectedSize)
		_, err := hex.Decode(result, []byte(value))
		if err != nil {
			return nil, err
		}
		return result, nil
	case DisplayFormatNumber:
		result := make([]byte, expectedSize)
		number, err := strconv.Atoi(value)
		if err != nil {
			return nil, err
		}
		if expectedSize == 8 {
			util.GetEndian().PutUint64(result, uint64(number))
		} else if expectedSize == 4 {
			util.GetEndian().PutUint32(result, uint32(number))
		} else if expectedSize == 2 {
			util.GetEndian().PutUint16(result, uint16(number))
		} else if expectedSize == 1 {
			result[0] = byte(number)
		} else {
			return nil, fmt.Errorf("unsupported number size %d (only 1, 2, 4 and 8 are supported)", expectedSize)
		}
		return result, nil
	default:
		result := make([]byte, expectedSize)
		_, err := hex.Decode(result, []byte(value)[:expectedSize*2])
		if err != nil {
			return nil, err
		}
		return result, nil
	}
}
