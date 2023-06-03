package maps

import "github.com/cilium/ebpf"

func IsPerCPU(mt ebpf.MapType) bool {
	return mt == ebpf.PerCPUHash || mt == ebpf.PerCPUArray || mt == ebpf.LRUCPUHash || mt == ebpf.PerCPUCGroupStorage
}

var lookupSupported = map[ebpf.MapType]bool{
	ebpf.UnspecifiedMap:      false,
	ebpf.Hash:                true,
	ebpf.Array:               true,
	ebpf.ProgramArray:        false,
	ebpf.PerfEventArray:      false,
	ebpf.PerCPUHash:          true,
	ebpf.PerCPUArray:         true,
	ebpf.StackTrace:          false,
	ebpf.CGroupArray:         false,
	ebpf.LRUHash:             false,
	ebpf.LRUCPUHash:          false,
	ebpf.LPMTrie:             false,
	ebpf.ArrayOfMaps:         false,
	ebpf.HashOfMaps:          false,
	ebpf.DevMap:              false,
	ebpf.SockMap:             false,
	ebpf.CPUMap:              false,
	ebpf.XSKMap:              false,
	ebpf.SockHash:            false,
	ebpf.CGroupStorage:       false,
	ebpf.ReusePortSockArray:  false,
	ebpf.PerCPUCGroupStorage: false,
	ebpf.Queue:               false,
	ebpf.Stack:               false,
	ebpf.SkStorage:           false,
	ebpf.DevMapHash:          false,
	ebpf.StructOpsMap:        false,
	ebpf.RingBuf:             false,
	ebpf.InodeStorage:        false,
	ebpf.TaskStorage:         false,
}

func IsLookupSupported(mt ebpf.MapType) bool {
	supported, ok := lookupSupported[mt]
	return ok && supported
}
