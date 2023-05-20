package progs

import (
	"context"
	"github.com/cilium/ebpf"
	"time"
)

type progWatcher struct {
	checkInterval time.Duration
	progs         []ProgInfo
	isRunning     bool
}

type ProgWatcher interface {
	Run(ctx context.Context)
	GetProgs() []ProgInfo
}

func NewWatcher(checkInterval time.Duration) ProgWatcher {
	return &progWatcher{
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
				pw.progs = pw.fetchProgs()
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

func (pw *progWatcher) GetProgs() []ProgInfo {
	if pw.progs == nil {
		return pw.fetchProgs()
	}
	return pw.progs
}

func (pw *progWatcher) fetchProgs() []ProgInfo {
	var currID ebpf.ProgramID = 0
	var err error
	var progs []ProgInfo
	for true {
		currID, err = ebpf.ProgramGetNextID(currID)
		if err != nil {
			break
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
	return progs
}

func progInfoErr(id ebpf.ProgramID, err error) ProgInfo {
	return ProgInfo{
		ID:    id,
		Info:  nil,
		Error: err,
	}
}
