package tasks

import (
	"context"
	"github.com/cilium/ebpf"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	"os"
	"runtime"
	"strconv"
	"time"
	"unsafe"
)

type TaskInfo struct {
	PID         uint32
	FD          uint32
	ProgramID   ebpf.ProgramID
	Type        TaskFdType
	Name        string
	ProbeOffset uint64
	ProbeAddr   uint64
}

type TaskWatcher interface {
	Run(ctx context.Context, refreshInterval time.Duration)
	GetTasks() ([]*TaskInfo, error)
}

type taskWatcher struct {
	tasks       []*TaskInfo
	error       error
	isRunning   bool
	procDirName string
}

func (tw *taskWatcher) Run(ctx context.Context, refreshInterval time.Duration) {
	if tw.isRunning {
		return
	}
	go func() {
		tw.isRunning = true
		ticker := time.NewTicker(refreshInterval)
		ctx.Done()
		for {
			select {
			case <-ticker.C:
				tw.tasks, tw.error = fetchTasks(tw.procDirName)
			case <-ctx.Done():
				tw.isRunning = false
				return
			}
		}
	}()
}

func (tw *taskWatcher) GetTasks() ([]*TaskInfo, error) {
	if tw.tasks == nil && tw.error == nil {
		return fetchTasks(tw.procDirName)
	}
	return tw.tasks, tw.error
}

func NewTaskWatcher() TaskWatcher {
	return &taskWatcher{
		procDirName: "/proc",
	}
}

type taskFdQuery struct {
	Pid   uint32
	Fd    uint32
	Flags uint32

	BufLen uint32
	Buf    uint64

	ProgId      uint32
	FdType      TaskFdType
	ProbeOffset uint64
	ProbeAddr   uint64
}

func fetchTasks(procDirName string) ([]*TaskInfo, error) {
	procDir, err := os.ReadDir(procDirName)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open "+procDirName)
	}

	var tasks []*TaskInfo

	for _, procDirEntry := range procDir {
		pid, err := strconv.Atoi(procDirEntry.Name())
		if err != nil {
			continue
		}

		fdDir, err := os.ReadDir(procDirName + "/" + procDirEntry.Name() + "/fd")
		if err != nil {
			continue
		}

		for _, fdDirEntry := range fdDir {
			fdNo, err := strconv.Atoi(fdDirEntry.Name())
			if err != nil {
				continue
			}
			bufLen := 4096
			buf := make([]byte, bufLen)

			taskAttr := &taskFdQuery{
				Pid:    uint32(pid),
				Fd:     uint32(fdNo),
				Flags:  0,
				BufLen: uint32(bufLen),
				Buf:    uint64(uintptr(unsafe.Pointer(&buf[0]))),
			}

			_, err = callBPF(unix.BPF_TASK_FD_QUERY, unsafe.Pointer(taskAttr), unsafe.Sizeof(*taskAttr))
			if err != nil {
				continue
			}

			// cut buf to the actual length
			buf = buf[:taskAttr.BufLen]

			tasks = append(tasks, &TaskInfo{
				PID:         taskAttr.Pid,
				FD:          taskAttr.Fd,
				ProgramID:   ebpf.ProgramID(taskAttr.ProgId),
				Type:        taskAttr.FdType,
				Name:        string(buf),
				ProbeOffset: taskAttr.ProbeOffset,
				ProbeAddr:   taskAttr.ProbeAddr,
			})

		}
	}

	return tasks, nil
}

func callBPF(cmd int, attr unsafe.Pointer, size uintptr) (uintptr, error) {
	for {
		r1, _, errNo := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(attr), size)
		runtime.KeepAlive(attr)

		// As of ~4.20 the verifier can be interrupted by a signal,
		// and returns EAGAIN in that case.
		if errNo == unix.EAGAIN && cmd == unix.BPF_PROG_LOAD {
			continue
		}

		var err error
		if errNo != 0 {
			err = errors.New("bpf syscall failed: " + errNo.Error())
		}

		return r1, err
	}
}
