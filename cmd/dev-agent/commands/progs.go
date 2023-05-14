package commands

import (
	"fmt"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/progs"
	"time"
)

type ProgsCommands struct {
	ProgsRepo progs.ProgWatcher
}

func (pc *ProgsCommands) ProgsList() error {
	fmt.Println("ID\tType\tTag\tRunCount\tRunTime\tAvgRunTime")
	for _, prog := range pc.ProgsRepo.GetProgs() {
		if prog.Error != nil {
			fmt.Printf("%d\t%v\n", prog.ID, prog.Error)
			continue
		}
		prog.Info.MapIDs()
		runCount, _ := prog.Info.RunCount()
		runTime, _ := prog.Info.Runtime()
		var avgRunTime time.Duration
		if runCount > 0 {
			avgRunTime = runTime / time.Duration(runCount)
		}
		fmt.Printf(
			"%d\t%s\t%v\t%v\t%d\t%s\t%s\n",
			prog.ID,
			prog.Info.Name,
			prog.Info.Type.String(),
			prog.Info.Tag,
			runCount,
			runTime.String(),
			avgRunTime,
		)
	}
	return nil
}
