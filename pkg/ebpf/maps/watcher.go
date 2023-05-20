package maps

import (
	"context"
	"github.com/cilium/ebpf"
	"time"
)

type mapsWatcher struct {
	checkInterval time.Duration
	maps          []*MapInfo
	isRunning     bool
}

type MapsWatcher interface {
	Run(ctx context.Context)
	GetMaps() []*MapInfo
	GetMap(id ebpf.MapID) *MapInfo
}

func NewWatcher(checkInterval time.Duration) MapsWatcher {
	return &mapsWatcher{
		checkInterval: checkInterval,
	}
}

func (pw *mapsWatcher) Run(ctx context.Context) {
	if pw.isRunning {
		return
	}
	go func() {
		pw.isRunning = true
		ticker := time.NewTicker(pw.checkInterval)
		ctx.Done()
		for {
			select {
			case <-ticker.C:
				pw.maps = pw.fetchMaps()
			case <-ctx.Done():
				pw.isRunning = false
				return
			}
		}
	}()
}

type MapInfo struct {
	ID         ebpf.MapID
	Error      error
	Name       string
	Type       ebpf.MapType
	Flags      uint32
	IsPinned   bool
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
}

func (pw *mapsWatcher) GetMaps() []*MapInfo {
	if pw.maps == nil {
		return pw.fetchMaps()
	}
	return pw.maps
}

func (pw *mapsWatcher) GetMap(id ebpf.MapID) *MapInfo {
	maps := pw.GetMaps()
	for _, m := range maps {
		if m.ID == id {
			return m
		}
	}
	return nil
}

func (pw *mapsWatcher) fetchMaps() []*MapInfo {
	var currID ebpf.MapID = 0
	var err error
	var maps []*MapInfo
	for true {
		currID, err = ebpf.MapGetNextID(currID)
		if err != nil {
			break
		}
		emap, err2 := ebpf.NewMapFromID(currID)
		if err2 != nil {
			maps = append(maps, mapInfoErr(currID, err2))
			continue
		}
		info, err2 := emap.Info()
		name := ""
		if info != nil {
			name = info.Name
		}
		maps = append(maps, &MapInfo{
			ID:         currID,
			Error:      err2,
			Name:       name,
			Type:       emap.Type(),
			Flags:      emap.Flags(),
			IsPinned:   emap.IsPinned(),
			KeySize:    emap.KeySize(),
			ValueSize:  emap.ValueSize(),
			MaxEntries: emap.MaxEntries(),
		})
		_ = emap.Close()
	}
	return maps
}

func mapInfoErr(id ebpf.MapID, err error) *MapInfo {
	return &MapInfo{
		ID:    id,
		Error: err,
	}
}
