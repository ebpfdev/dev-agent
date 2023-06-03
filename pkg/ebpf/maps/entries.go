package maps

import (
	"github.com/cilium/ebpf"
	sortp "sort"
)

type MapEntries struct {
	Entries []*MapEntry
}

type MapEntry struct {
	Key       []byte
	CPUValues [][]byte
	Value     []byte
}

func GetEntries(id ebpf.MapID, sort bool) (*MapEntries, error) {
	emap, err := ebpf.NewMapFromID(id)
	if err != nil {
		return nil, err
	}

	entries := make([]*MapEntry, 0)

	if !IsLookupSupported(emap.Type()) {
		return &MapEntries{[]*MapEntry{}}, nil
	}

	var key []byte
	mapIterator := emap.Iterate()
	if IsPerCPU(emap.Type()) {
		var bufSlice [][]byte
		for mapIterator.Next(&key, &bufSlice) {
			values := make([][]byte, len(bufSlice))
			for i, value := range bufSlice {
				values[i] = value[:]
			}
			entries = append(entries, &MapEntry{
				Key:       key[:],
				CPUValues: values,
			})
		}
	} else {
		var buf []byte
		for mapIterator.Next(&key, &buf) {
			entries = append(entries, &MapEntry{
				Key:   key[:],
				Value: buf[:],
			})
		}
	}

	if sort {
		sortp.SliceStable(entries, func(i, j int) bool {
			iKey := entries[i].Key
			jKey := entries[j].Key
			for k := 0; k < len(iKey) && k < len(jKey); k++ {
				if iKey[k] < jKey[k] {
					return true
				}
				if iKey[k] > jKey[k] {
					return false
				}
			}
			return len(iKey) < len(jKey)
		})
	}

	return &MapEntries{entries}, mapIterator.Err()
}

func CountEntries(id ebpf.MapID) (int, error) {
	count := 0
	emap, err := ebpf.NewMapFromID(id)
	if err != nil {
		return 0, err
	}

	if !IsLookupSupported(emap.Type()) {
		return 0, nil
	}

	var key []byte
	var buf []byte
	mapIterator := emap.Iterate()
	for mapIterator.Next(&key, &buf) {
		count++
	}
	return count, mapIterator.Err()
}
