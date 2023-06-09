package graph

import (
	"github.com/cilium/ebpf"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/maps"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/progs"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/tasks"
	"github.com/ebpfdev/dev-agent/pkg/graph/model"
	"strconv"
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
		IsPinned:          len(m.Pins) > 0,
		Pins:              m.Pins,
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

func toMapsFormat(format model.MapEntryFormat) maps.DisplayFormat {
	switch format {
	case model.MapEntryFormatString:
		return maps.DisplayFormatString
	case model.MapEntryFormatHex:
		return maps.DisplayFormatHex
	case model.MapEntryFormatNumber:
		return maps.DisplayFormatNumber
	default:
		return maps.DisplayFormatHex
	}
}

func taskInfoToModel(ti *tasks.TaskInfo) *model.Task {
	probeOffsetStr := "0x" + strconv.FormatUint(ti.ProbeOffset, 16)
	probeAddrStr := "0x" + strconv.FormatUint(ti.ProbeAddr, 16)

	return &model.Task{
		Pid:         int(ti.PID),
		Fd:          int(ti.FD),
		Type:        ti.Type.String(),
		Name:        &ti.Name,
		ProbeOffset: &probeOffsetStr,
		ProbeAddr:   &probeAddrStr,
	}
}

func buildConnectedGraph(progsMap map[ebpf.ProgramID]*progs.ProgInfo, mapsMap map[ebpf.MapID]*maps.MapInfo) *model.ConnectedGraph {
	result := &model.ConnectedGraph{}
	for _, info := range progsMap {
		result.Programs = append(result.Programs, progInfoToModel(info))
	}
	for _, info := range mapsMap {
		result.Maps = append(result.Maps, mapInfoToModel(info))
	}
	return result
}
