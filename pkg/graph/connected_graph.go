package graph

import (
	"github.com/cilium/ebpf"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/maps"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/progs"
	"github.com/ebpfdev/dev-agent/pkg/graph/model"
)

func (r *queryResolver) resolveConnectedGraph(from int, fromType model.IDType) (map[ebpf.ProgramID]*progs.ProgInfo, map[ebpf.MapID]*maps.MapInfo, error) {
	progsList, err := r.ProgsRepository.GetProgs()
	if err != nil {
		return nil, nil, err
	}
	emapsList, err := r.MapsRepository.GetMaps()
	if err != nil {
		return nil, nil, err
	}

	mapToProgs := make(map[ebpf.MapID][]ebpf.ProgramID)
	for _, prog := range progsList {
		if prog.Info != nil {
			mapIDs, _ := prog.Info.MapIDs()
			for _, mapID := range mapIDs {
				mapToProgs[mapID] = append(mapToProgs[mapID], prog.ID)
			}
		}
	}

	progsMap := make(map[ebpf.ProgramID]*progs.ProgInfo)
	emapsMap := make(map[ebpf.MapID]*maps.MapInfo)

	var resolveMap func(id ebpf.MapID)
	var resolveProg func(id ebpf.ProgramID)

	resolveMap = func(id ebpf.MapID) {
		if _, ok := emapsMap[id]; ok {
			return
		}
		for _, emap := range emapsList {
			if emap.ID == id {
				emapsMap[id] = emap
				progIDs, _ := mapToProgs[id]
				for _, progID := range progIDs {
					resolveProg(progID)
				}
				return
			}
		}
	}

	resolveProg = func(id ebpf.ProgramID) {
		if _, ok := progsMap[id]; ok {
			return
		}
		for _, prog := range progsList {
			if prog.ID == id {
				progsMap[id] = &prog
				if prog.Info == nil {
					return
				}
				mapIDs, _ := prog.Info.MapIDs()
				for _, mapID := range mapIDs {
					resolveMap(mapID)
				}
				return
			}
		}
	}

	switch fromType {
	case model.IDTypeProgram:
		resolveProg(ebpf.ProgramID(from))
	case model.IDTypeMap:
		resolveMap(ebpf.MapID(from))
	}

	return progsMap, emapsMap, nil
}
