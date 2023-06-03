package graph

import (
	"github.com/ebpfdev/dev-agent/pkg/ebpf/maps"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/progs"
	"github.com/ebpfdev/dev-agent/pkg/graph/model"
)

func progInfoToModel(prog *progs.ProgInfo) *model.Program {
	if prog.Info == nil {
		errs := prog.Error.Error()
		return &model.Program{
			ID:    int(prog.ID),
			Error: &errs,
		}
	}

	runTime, _ := prog.Info.Runtime()
	runTimeSec := runTime.Seconds()
	runCount, _ := prog.Info.RunCount()
	runCountInt := int(runCount)
	btfID, _ := prog.Info.BTFID()
	btfIDInt := int(btfID)

	mapIDs, _ := prog.Info.MapIDs()
	emaps := make([]*model.Map, len(mapIDs))
	for j, mapID := range mapIDs {
		emaps[j] = &model.Map{
			ID: int(mapID),
		}
	}

	return &model.Program{
		ID:          int(prog.ID),
		Name:        &prog.Info.Name,
		Type:        prog.Type.String(),
		Tag:         &prog.Info.Tag,
		RunTime:     &runTimeSec,
		RunCount:    &runCountInt,
		BtfID:       &btfIDInt,
		VerifierLog: &prog.VerifierLog,
		IsPinned:    &prog.IsPinned,
		Maps:        emaps,
	}
}

func mapInfoToModel(m *maps.MapInfo) *model.Map {
	if m.Error != nil {
		errString := m.Error.Error()
		return &model.Map{
			ID:    int(m.ID),
			Error: &errString,
		}
	}
	flags := int(m.Flags)
	keySize := int(m.KeySize)
	valueSize := int(m.ValueSize)
	maxEntries := int(m.MaxEntries)
	return &model.Map{
		ID:                int(m.ID),
		Name:              &m.Name,
		Type:              m.Type.String(),
		Flags:             &flags,
		IsPinned:          &m.IsPinned,
		KeySize:           &keySize,
		ValueSize:         &valueSize,
		MaxEntries:        &maxEntries,
		IsPerCPU:          maps.IsPerCPU(m.Type),
		IsLookupSupported: maps.IsLookupSupported(m.Type),
	}
}

func formatValue(format model.MapEntryFormat, value []byte) string {
	switch format {
	case model.MapEntryFormatString:
		return maps.FormatBytes(maps.DisplayFormatString, value)
	case model.MapEntryFormatHex:
		return maps.FormatBytes(maps.DisplayFormatHex, value)
	case model.MapEntryFormatNumber:
		return maps.FormatBytes(maps.DisplayFormatNumber, value)
	default:
		return maps.FormatBytes(maps.DisplayFormatHex, value)
	}
}
