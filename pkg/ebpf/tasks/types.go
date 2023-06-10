package tasks

//go:generate stringer -output types_string.go -type=TaskFdType

type TaskFdType uint32

const (
	RawTracepoint TaskFdType = iota
	Tracepoint
	Kprobe
	Kretprobe
	Uprobe
	Uretprobe
)
