package maps

import (
	"fmt"
	"github.com/cilium/ebpf"
	"regexp"
	"strconv"
	"strings"
)

type MapExportConfiguration struct {
	StartID          int
	EndID            int
	MetricNameRegexp regexp.Regexp
	KeyFormat        DisplayFormat
}

func (c *MapExportConfiguration) MatchMap(id ebpf.MapID, name string) bool {
	if c.StartID >= 0 && int(id) < c.StartID {
		return false
	}
	if c.EndID >= 0 && int(id) > c.EndID {
		return false
	}
	return c.MetricNameRegexp.MatchString(name)
}

func ParseMapExportConfiguration(config string) (*MapExportConfiguration, error) {
	parts := strings.Split(config, ":")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid format: %s, should be <id_start?>-<id_end?>:<metric_name_regexp>:<key_format>", config)
	}

	rangeStr := parts[0]
	keyFormat := parts[len(parts)-1]
	metricNameRegexp := strings.Join(parts[1:len(parts)-1], ":")

	idStart, idEnd, err := parseRange(rangeStr)
	if err != nil {
		return nil, err
	}
	metricNameRegexpCompiled, err := regexp.Compile(metricNameRegexp)
	if err != nil {
		return nil, err
	}
	keyFormatParsed, err := parseDisplayFormat(keyFormat)
	if err != nil {
		return nil, err
	}

	return &MapExportConfiguration{
		StartID:          idStart,
		EndID:            idEnd,
		MetricNameRegexp: *metricNameRegexpCompiled,
		KeyFormat:        keyFormatParsed,
	}, nil
}

func parseDisplayFormat(s string) (DisplayFormat, error) {
	switch strings.ToLower(s) {
	case "string":
		return DisplayFormatString, nil
	case "number":
		return DisplayFormatNumber, nil
	case "hex":
		return DisplayFormatHex, nil
	default:
		return DisplayFormatHex, fmt.Errorf("invalid format: %s, should be string, number or hex", s)
	}
}

func parseRange(rangeStr string) (int, int, error) {
	var startID, endID int
	var err error
	rangeParts := strings.SplitN(rangeStr, "-", 2)
	if len(rangeParts) != 2 {
		return -1, -1, fmt.Errorf("ID range is invalid: %s", rangeStr)
	}
	if rangeParts[0] == "" {
		startID = -1
	} else {
		startID, err = strconv.Atoi(rangeParts[0])
		if err != nil {
			return -1, -1, fmt.Errorf("start ID is invalid: %s", rangeStr)
		}
	}
	if rangeParts[1] == "" {
		endID = -1
	} else {
		endID, err = strconv.Atoi(rangeParts[1])
		if err != nil {
			return startID, -1, fmt.Errorf("end ID is invalid: %s", rangeStr)
		}
	}
	return startID, endID, nil
}
