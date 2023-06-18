package maps

import (
	"context"
	"errors"
	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"os"
	"path/filepath"
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
	bpfDir          string
}

type MapsWatcher interface {
	Run(ctx context.Context, refreshInterval time.Duration)
	GetMaps() ([]*MapInfo, error)
	GetMap(id ebpf.MapID) (*MapInfo, error)
	RegisterMetrics(registry *prometheus.Registry)
	AddExportConfig(config *MapExportConfiguration)
	PinMap(id ebpf.MapID, path string) error
	UpdateMapValue(id ebpf.MapID, key string, cpu *int, value string, keyFormat DisplayFormat, mapsFormat DisplayFormat) error
	CreateMapValue(id ebpf.MapID, key string, values []string, keyFormat DisplayFormat, mapsFormat DisplayFormat) error
	DeleteMapValue(id ebpf.MapID, key string, keyFormat DisplayFormat) error
}

type WatcherOpts struct {
	RefreshInterval time.Duration
}

func NewWatcher(logger zerolog.Logger, bpfDir string) MapsWatcher {
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
		bpfDir:          bpfDir,
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
	Pins       []string
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

func (pw *mapsWatcher) PinMap(id ebpf.MapID, path string) error {
	emap, err := ebpf.NewMapFromID(id)
	if err != nil {
		return err
	}
	return emap.Pin(path)
}

func (pw *mapsWatcher) CreateMapValue(id ebpf.MapID, key string, values []string, keyFormat DisplayFormat, mapsFormat DisplayFormat) error {
	emap, err := ebpf.NewMapFromID(id)
	if err != nil {
		return err
	}
	if !IsPerCPU(emap.Type()) && len(values) != 1 {
		return errors.New("map is not percpu, but multiple values were provided")
	}

	keyBytes, err := RestoreBytes(keyFormat, key, emap.KeySize())
	if err != nil {
		return err
	}
	valueBytesSlice := make([][]byte, len(values))
	for i, value := range values {
		valueBytes, err := RestoreBytes(mapsFormat, value, emap.ValueSize())
		if err != nil {
			return err
		}
		valueBytesSlice[i] = valueBytes
	}
	if IsPerCPU(emap.Type()) {
		return emap.Update(keyBytes, valueBytesSlice, ebpf.UpdateNoExist)
	} else {
		return emap.Update(keyBytes, valueBytesSlice[0], ebpf.UpdateNoExist)
	}
}

func (pw *mapsWatcher) UpdateMapValue(id ebpf.MapID, key string, cpu *int, value string, keyFormat DisplayFormat, mapsFormat DisplayFormat) error {
	emap, err := ebpf.NewMapFromID(id)
	if err != nil {
		return err
	}
	keyBytes, err := RestoreBytes(keyFormat, key, emap.KeySize())
	if err != nil {
		return err
	}
	valueBytes, err := RestoreBytes(mapsFormat, value, emap.ValueSize())
	if err != nil {
		return err
	}
	if IsPerCPU(emap.Type()) && cpu == nil {
		return errors.New("cpu index is required for percpu maps")
	}
	if cpu == nil {
		return emap.Update(keyBytes, valueBytes, ebpf.UpdateAny)
	} else {
		var currentValue [][]byte
		err = emap.Lookup(keyBytes, &currentValue)
		if err != nil {
			return err
		}
		if len(currentValue) <= *cpu {
			return errors.New("cpu index out of range")
		}
		currentValue[*cpu] = valueBytes
		return emap.Update(keyBytes, currentValue, ebpf.UpdateAny)
	}
}

func (pw *mapsWatcher) DeleteMapValue(id ebpf.MapID, key string, keyFormat DisplayFormat) error {
	emap, err := ebpf.NewMapFromID(id)
	if err != nil {
		return err
	}
	keyBytes, err := RestoreBytes(keyFormat, key, emap.KeySize())
	if err != nil {
		return err
	}
	return emap.Delete(keyBytes)
}

func getPins(bpfDir string) map[ebpf.MapID][]string {
	result := make(map[ebpf.MapID][]string)
	_ = filepath.Walk(bpfDir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		pinnedMap, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{
			ReadOnly: true,
		})
		defer pinnedMap.Close()
		if err != nil {
			return nil
		}
		mapInfo, err := pinnedMap.Info()
		if err != nil {
			return nil
		}
		id, ok := mapInfo.ID()
		if !ok {
			return nil
		}
		result[id] = append(result[id], path)
		return nil
	})
	return result
}

func (pw *mapsWatcher) fetchMaps() ([]*MapInfo, error) {
	var currID ebpf.MapID = 0
	var err error
	var maps []*MapInfo
	pw.log.Debug().Msg("fetching maps")

	// maps pinned by path
	pinnedMaps := getPins(pw.bpfDir)

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
		defer emap.Close()

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
			Pins:       pinnedMaps[currID],
			KeySize:    emap.KeySize(),
			ValueSize:  emap.ValueSize(),
			MaxEntries: emap.MaxEntries(),
		})

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
