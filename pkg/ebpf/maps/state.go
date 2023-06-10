package maps

import (
	"context"
	"errors"
	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"os"
	"time"
)

type mapsWatcher struct {
	log             zerolog.Logger
	refreshInterval time.Duration
	maps            []*MapInfo
	error           error
	isRunning       bool

	mapsCount       *prometheus.GaugeVec
	mapEntriesCount *prometheus.GaugeVec
	mapEntryValues  *prometheus.GaugeVec
	exportConfigs   []*MapExportConfiguration
}

type MapsWatcher interface {
	Run(ctx context.Context, refreshInterval time.Duration)
	GetMaps() ([]*MapInfo, error)
	GetMap(id ebpf.MapID) (*MapInfo, error)
	RegisterMetrics(registry *prometheus.Registry)
	AddExportConfig(config *MapExportConfiguration)
}

type WatcherOpts struct {
	RefreshInterval time.Duration
}

func NewWatcher(logger zerolog.Logger) MapsWatcher {
	mapsCount := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "devagent",
		Subsystem: "ebpf",
		Name:      "map_count",
		Help:      "Number of eBPF maps",
	}, []string{"type"})
	mapEntriesCount := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "devagent",
		Subsystem: "ebpf",
		Name:      "map_entry_count",
		Help:      "Number of entries in an eBPF map",
	}, []string{"id", "name", "type"})
	mapEntryValues := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "devagent",
		Subsystem: "ebpf",
		Name:      "map_entry_value",
		Help:      "Value of an eBPF map entry",
	}, []string{"id", "name", "type", "key", "cpu"})

	return &mapsWatcher{
		log:             logger,
		mapsCount:       mapsCount,
		mapEntriesCount: mapEntriesCount,
		mapEntryValues:  mapEntryValues,
	}
}

func (pw *mapsWatcher) AddExportConfig(config *MapExportConfiguration) {
	pw.exportConfigs = append(pw.exportConfigs, config)
}

func (pw *mapsWatcher) RegisterMetrics(registry *prometheus.Registry) {
	err := registry.Register(pw.mapsCount)
	if err != nil {
		pw.log.Err(err).Msg("Failed to register map_count metric")
	}
	err = registry.Register(pw.mapEntriesCount)
	if err != nil {
		pw.log.Err(err).Msg("Failed to register map_entry_count metric")
	}
	err = registry.Register(pw.mapEntryValues)
	if err != nil {
		pw.log.Err(err).Msg("Failed to register map_entry_value metric")
	}
}

func (pw *mapsWatcher) Run(ctx context.Context, refreshInterval time.Duration) {
	if pw.isRunning {
		return
	}
	go func() {
		pw.isRunning = true
		ticker := time.NewTicker(refreshInterval)
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

	// maps count by type
	mapsCount := make(map[ebpf.MapType]int)
	defer func() {
		for k, v := range mapsCount {
			pw.mapsCount.WithLabelValues(k.String()).Set(float64(v))
		}
	}()

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

		mapsCount[emap.Type()]++

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

		for _, config := range pw.exportConfigs {
			if config.MatchMap(currID, name) {
				pw.exportMapEntries(currID, name, emap.Type(), config)
				break
			}
		}
	}
	return maps, nil
}

func mapInfoErr(id ebpf.MapID, err error) *MapInfo {
	return &MapInfo{
		ID:    id,
		Error: err,
	}
}
