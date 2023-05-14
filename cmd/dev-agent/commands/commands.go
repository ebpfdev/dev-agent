package commands

import (
	"github.com/ebpfdev/dev-agent/pkg/ebpf/maps"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/progs"
	"github.com/urfave/cli/v2"
	"time"
)

func App() *cli.App {
	progsRepo := progs.NewWatcher(1 * time.Second)
	mapsRepo := maps.NewWatcher(1 * time.Second)
	progsCommands := &ProgsCommands{
		ProgsRepo: progsRepo,
	}
	mapsCommands := &MapsCommands{
		MapsRepo: mapsRepo,
	}
	serverCommands := &ServerCommands{
		ProgsRepo: progsRepo,
		MapsRepo:  mapsRepo,
	}

	return &cli.App{
		Name: "phydev",
		Commands: []*cli.Command{
			{
				Name: "about",
				Action: func(c *cli.Context) error {
					println("phydev - development agent for eBPF programs")
					println("it enables browsing eBPF programs and maps")
					return nil
				},
			},
			{
				Name: "server",
				Action: func(c *cli.Context) error {
					return serverCommands.ServerStart()
				},
			},
			{
				Name: "inspect",
				Subcommands: []*cli.Command{
					{
						Name: "progs",
						Subcommands: []*cli.Command{
							{
								Name: "list",
								Action: func(c *cli.Context) error {
									return progsCommands.ProgsList()
								},
							},
						},
					},
					{
						Name: "maps",
						Subcommands: []*cli.Command{
							{
								Name: "list",
								Action: func(c *cli.Context) error {
									return mapsCommands.MapsList()
								},
							},
						},
					},
				},
			},
		},
	}
}
