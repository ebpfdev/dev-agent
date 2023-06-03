package graph

import (
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/maps"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/progs"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/util"
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
		IsPerCPU:          isPerCPU(m.Type),
		IsLookupSupported: isLookupSupported(m.Type),
	}
}

func formatValue(format model.MapEntryFormat, value []byte) string {
	switch format {
	case model.MapEntryFormatString:
		return string(value)
	case model.MapEntryFormatHex:
		return fmt.Sprintf("%x", value)
	case model.MapEntryFormatNumber:
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

func isPerCPU(mt ebpf.MapType) bool {
	return mt == ebpf.PerCPUHash || mt == ebpf.PerCPUArray || mt == ebpf.LRUCPUHash || mt == ebpf.PerCPUCGroupStorage
}

var lookupSupported = map[ebpf.MapType]bool{
	ebpf.UnspecifiedMap:      false,
	ebpf.Hash:                true,
	ebpf.Array:               true,
	ebpf.ProgramArray:        false,
	ebpf.PerfEventArray:      false,
	ebpf.PerCPUHash:          true,
	ebpf.PerCPUArray:         true,
	ebpf.StackTrace:          false,
	ebpf.CGroupArray:         false,
	ebpf.LRUHash:             false,
	ebpf.LRUCPUHash:          false,
	ebpf.LPMTrie:             false,
	ebpf.ArrayOfMaps:         false,
	ebpf.HashOfMaps:          false,
	ebpf.DevMap:              false,
	ebpf.SockMap:             false,
	ebpf.CPUMap:              false,
	ebpf.XSKMap:              false,
	ebpf.SockHash:            false,
	ebpf.CGroupStorage:       false,
	ebpf.ReusePortSockArray:  false,
	ebpf.PerCPUCGroupStorage: false,
	ebpf.Queue:               false,
	ebpf.Stack:               false,
	ebpf.SkStorage:           false,
	ebpf.DevMapHash:          false,
	ebpf.StructOpsMap:        false,
	ebpf.RingBuf:             false,
	ebpf.InodeStorage:        false,
	ebpf.TaskStorage:         false,
}

func isLookupSupported(mt ebpf.MapType) bool {
	supported, ok := lookupSupported[mt]
	return ok && supported
}
