package commands

import (
	"github.com/ebpfdev/dev-agent/pkg/ebpf/maps"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/progs"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/tasks"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v2"
)

func App() *cli.App {
	logger := log.Logger.Level(zerolog.InfoLevel)
	progsRepo := progs.NewWatcher(logger)
	mapsRepo := maps.NewWatcher(logger)
	tasksRepo := tasks.NewTaskWatcher()
	progsCommands := &ProgsCommands{
		ProgsRepo: progsRepo,
	}
	mapsCommands := &MapsCommands{
		MapsRepo: mapsRepo,
	}
	serverCommands := &ServerCommands{
		ProgsRepo: progsRepo,
		MapsRepo:  mapsRepo,
		TasksRepo: tasksRepo,
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
						Name:     "path-prefix",
						Category: "Server",
						Usage:    "path prefix for the web ui to access the server",
						Value:    "/",
					},
					&cli.BoolFlag{
						Name:  "skip-welcome",
						Usage: "skip welcome message",
					},
					&cli.MultiStringFlag{
						Target: &cli.StringSliceFlag{
							Name:     "entries-to-metrics",
							Category: "Metrics",
							Usage: "(experimental, api may change)\n\tConfigure which map entries should be exposed as metrics, " +
								"in the format: id_start-id_end:metric_name_regexp:key_format.\n\t" +
								"Example: '-:.+:string' to export any map with non-empty name while treating key as string.\n\t" +
								"or '10-:.*:hex' to export any map after ID 10 with key represented in HEX format\n\t" +
								"Available key formats: string, number, hex\n\t" +
								"If a map matches multiple entries, the first one is used.",
							Aliases: []string{"etm"},
						},
					},
				},
				Action: func(c *cli.Context) error {
					for _, etm := range c.StringSlice("entries-to-metrics") {
						etmConfig, err := maps.ParseMapExportConfiguration(etm)
						if err != nil {
							return err
						}
						mapsRepo.AddExportConfig(etmConfig)
					}

					return serverCommands.ServerStart(&ServerStartOptions{
						PathPrefix:  c.String("path-prefix"),
						SkipWelcome: c.Bool("skip-welcome"),
					})
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
