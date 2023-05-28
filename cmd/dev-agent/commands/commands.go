package commands

import (
	"github.com/ebpfdev/dev-agent/pkg/ebpf/maps"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/progs"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
	"time"
)

func App() *cli.App {
	logger := log.Logger.Level(zerolog.InfoLevel)
	progsRepo := progs.NewWatcher(logger, 1*time.Second)
	mapsRepo := maps.NewWatcher(logger, 1*time.Second)
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
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "path-prefix",
						Usage: "path prefix for the web ui to access the server",
						Value: "/",
					},
				},
				Action: func(c *cli.Context) error {
					return serverCommands.ServerStart(c.String("path-prefix"))
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
