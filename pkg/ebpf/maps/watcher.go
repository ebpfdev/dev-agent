package maps

import (
	"context"
	"errors"
	"github.com/cilium/ebpf"
	"github.com/rs/zerolog"
	"os"
	"time"
)

type mapsWatcher struct {
	log           zerolog.Logger
	checkInterval time.Duration
	maps          []*MapInfo
	error         error
	isRunning     bool
}

type MapsWatcher interface {
	Run(ctx context.Context)
	GetMaps() ([]*MapInfo, error)
	GetMap(id ebpf.MapID) (*MapInfo, error)
}

func NewWatcher(logger zerolog.Logger, checkInterval time.Duration) MapsWatcher {
	return &mapsWatcher{
		log:           logger,
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
				pw.maps, pw.error = pw.fetchMaps()
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

func (pw *mapsWatcher) GetMaps() ([]*MapInfo, error) {
	if pw.maps == nil {
		return pw.fetchMaps()
	}
	return pw.maps, pw.error
}

func (pw *mapsWatcher) GetMap(id ebpf.MapID) (*MapInfo, error) {
	maps, err := pw.GetMaps()
	if err != nil {
		return nil, err
	}
	for _, m := range maps {
		if m.ID == id {
			return m, nil
		}
	}
	return nil, errors.New("map not found")
}

func (pw *mapsWatcher) fetchMaps() ([]*MapInfo, error) {
	var currID ebpf.MapID = 0
	var err error
	var maps []*MapInfo
	pw.log.Debug().Msg("fetching maps")
	for true {
		currID, err = ebpf.MapGetNextID(currID)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			pw.log.Err(err).Msg("failed to get next map ID")
			return maps, err
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
	return maps, nil
}

func mapInfoErr(id ebpf.MapID, err error) *MapInfo {
	return &MapInfo{
		ID:    id,
		Error: err,
	}
}
