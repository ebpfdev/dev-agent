package main

import (
	"github.com/ebpfdev/dev-agent/cmd/dev-agent/commands"
	"log"
	"os"
)

func main() {
	if err := commands.App().Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
