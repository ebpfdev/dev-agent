package maps

import (
	"github.com/cilium/ebpf"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/util"
	"strconv"
)

func (pw *mapsWatcher) exportMapEntries(id ebpf.MapID, name string, typ ebpf.MapType, config *MapExportConfiguration) {
	mapEntries, err := GetEntries(id, false)
	if err != nil {
		pw.log.Err(err).Msgf("failed to get map entries for map %d", id)
		return
	}

	pw.mapEntriesCount.
		WithLabelValues(strconv.Itoa(int(id)), name, typ.String()).
		Set(float64(len(mapEntries.Entries)))

	for _, entry := range mapEntries.Entries {
		key := FormatBytes(config.KeyFormat, entry.Key)

		if len(entry.CPUValues) > 0 {
			for cpu, value := range entry.CPUValues {
				if len(value) <= 8 {
					buf := make([]byte, 8)
					copy(buf, value)
					pw.mapEntryValues.
						WithLabelValues(
							strconv.Itoa(int(id)),
							name,
							typ.String(),
							key,
							strconv.Itoa(cpu)).
						Set(float64(util.GetEndian().Uint64(buf)))
				}
			}
		} else {
			buf := make([]byte, 8)
			copy(buf, entry.Value)
			pw.mapEntryValues.
				WithLabelValues(
					strconv.Itoa(int(id)),
					name,
					typ.String(),
					key,
					"").
				Set(float64(util.GetEndian().Uint64(buf)))
		}
	}

}
