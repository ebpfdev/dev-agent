package progs

import (
	"context"
	"errors"
	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
	"strconv"
	"time"
)

type progWatcher struct {
	log          zerolog.Logger
	progs        []ProgInfo
	error        error
	isRunning    bool
	progRunCount *prometheus.GaugeVec
	progRunTime  *prometheus.GaugeVec
	progsCount   *prometheus.GaugeVec
}

type ProgWatcher interface {
	Run(ctx context.Context, refreshInterval time.Duration)
	GetProgs() ([]ProgInfo, error)
	GetProg(id ebpf.ProgramID) (*ProgInfo, error)
	RegisterMetrics(registry *prometheus.Registry)
}

func NewWatcher(logger zerolog.Logger) ProgWatcher {
	progRunCount := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "devagent",
		Subsystem: "ebpf",
		Name:      "prog_run_count",
		Help:      "Number of times an eBPF program has been run",
	}, []string{"id", "type", "tag", "name"})
	progRunTime := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "devagent",
		Subsystem: "ebpf",
		Name:      "prog_run_time",
		Help:      "Total time spent running eBPF programs",
	}, []string{"id", "type", "tag", "name"})
	progsCount := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "devagent",
		Subsystem: "ebpf",
		Name:      "prog_count",
		Help:      "Number of eBPF programs",
	}, []string{"type"})

	return &progWatcher{
		log:          logger,
		progRunCount: progRunCount,
		progRunTime:  progRunTime,
		progsCount:   progsCount,
	}
}

func (pw *progWatcher) RegisterMetrics(registry *prometheus.Registry) {
	err := registry.Register(pw.progRunCount)
	if err != nil {
		log.Err(err).Msg("failed to register prog_run_count metric")
	}
	err = registry.Register(pw.progRunTime)
	if err != nil {
		log.Err(err).Msg("failed to register prog_run_time metric")
	}
	err = registry.Register(pw.progsCount)
	if err != nil {
		log.Err(err).Msg("failed to register prog_count metric")
	}
}

func (pw *progWatcher) Run(ctx context.Context, refreshInterval time.Duration) {
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
				pw.progs, pw.error = pw.fetchProgs()
			case <-ctx.Done():
				pw.isRunning = false
				return
			}
		}
	}()
}

type ProgInfo struct {
	ID          ebpf.ProgramID
	Info        *ebpf.ProgramInfo
	Error       error
	VerifierLog string
	Type        ebpf.ProgramType
	IsPinned    bool
}

func (pw *progWatcher) GetProgs() ([]ProgInfo, error) {
	if pw.progs == nil {
		return pw.fetchProgs()
	}
	return pw.progs, pw.error
}

func (pw *progWatcher) GetProg(id ebpf.ProgramID) (*ProgInfo, error) {
	progs, err := pw.GetProgs()
	if err != nil {
		return nil, err
	}
	for _, prog := range progs {
		if prog.ID == id {
			return &prog, nil
		}
	}
	return nil, errors.New("program not found")
}

func (pw *progWatcher) fetchProgs() ([]ProgInfo, error) {
	var currID ebpf.ProgramID = 0
	var err error
	var progs []ProgInfo
	pw.log.Debug().Msg("fetching progs")

	// progs count by type
	var progsCount = map[ebpf.ProgramType]uint64{}
	defer func() {
		for progType, count := range progsCount {
			pw.progsCount.WithLabelValues(progType.String()).Set(float64(count))
		}
	}()

	for true {
		currID, err = ebpf.ProgramGetNextID(currID)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			pw.log.Err(err).Msg("failed to get next program ID")
			return progs, err
		}
		prog, err2 := ebpf.NewProgramFromID(currID)
		if err2 != nil {
			progs = append(progs, progInfoErr(currID, err2))
			continue
		}
		info, err2 := prog.Info()

		runCount := uint64(0)
		runTime := time.Duration(0)
		var labelValues []string
		if info != nil {
			runCount, _ = info.RunCount()
			runTime, _ = info.Runtime()
			labelValues = []string{
				strconv.Itoa(int(currID)),
				prog.Type().String(),
				info.Tag,
				info.Name,
			}
		} else {
			labelValues = []string{
				strconv.Itoa(int(currID)),
				prog.Type().String(),
				"",
				"",
			}
		}

		pw.progRunCount.WithLabelValues(labelValues...).Set(float64(runCount))
		pw.progRunTime.WithLabelValues(labelValues...).Set(runTime.Seconds())
		progsCount[prog.Type()]++

		progs = append(progs, ProgInfo{
			ID:          currID,
			Type:        prog.Type(),
			IsPinned:    prog.IsPinned(),
			Info:        info,
			VerifierLog: prog.VerifierLog,
			Error:       err2,
		})
	}
	return progs, nil
}

func progInfoErr(id ebpf.ProgramID, err error) ProgInfo {
	return ProgInfo{
		ID:    id,
		Info:  nil,
		Error: err,
	}
}
