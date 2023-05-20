package commands

import (
	"fmt"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/maps"
)

type MapsCommands struct {
	MapsRepo maps.MapsWatcher
}

func (mc *MapsCommands) MapsList() error {
	fmt.Println("ID\tName\tType\tFlags\tIsPinned\tKeySize\tValueSize\tMaxEntries")
	for _, emap := range mc.MapsRepo.GetMaps() {
		if emap.Error != nil {
			fmt.Printf("%d\t%v\n", emap.ID, emap.Error)
			continue
		}
		fmt.Printf(
			"%d\t%s\t%s\t%d\t%v\t%d\t%d\t%d\n",
			emap.ID,
			emap.Name,
			emap.Type,
			emap.Flags,
			emap.IsPinned,
			emap.KeySize,
			emap.ValueSize,
			emap.MaxEntries,
		)
	}
	return nil
}
