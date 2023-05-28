package progs

import (
	"context"
	"errors"
	"github.com/cilium/ebpf"
	"github.com/rs/zerolog"
	"os"
	"time"
)

type progWatcher struct {
	log           zerolog.Logger
	checkInterval time.Duration
	progs         []ProgInfo
	error         error
	isRunning     bool
}

type ProgWatcher interface {
	Run(ctx context.Context)
	GetProgs() ([]ProgInfo, error)
	GetProg(id ebpf.ProgramID) (*ProgInfo, error)
}

func NewWatcher(logger zerolog.Logger, checkInterval time.Duration) ProgWatcher {
	return &progWatcher{
		log:           logger,
		checkInterval: checkInterval,
	}
}

func (pw *progWatcher) Run(ctx context.Context) {
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
