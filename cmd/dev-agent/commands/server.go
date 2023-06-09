package commands

import (
	"context"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/maps"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/progs"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/tasks"
	"github.com/ebpfdev/dev-agent/pkg/graph"
	"github.com/ebpfdev/dev-agent/pkg/graph/generated"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"log"
	"net/http"
	"os"
	"time"
)

type ServerCommands struct {
	MapsRepo  maps.MapsWatcher
	ProgsRepo progs.ProgWatcher
	TasksRepo tasks.TaskWatcher
}

type ServerStartOptions struct {
	PathPrefix  string
	SkipWelcome bool
}

const defaultPort = "8080"

func (sc *ServerCommands) ServerStart(options *ServerStartOptions) error {

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	registry := prometheus.NewRegistry()

	sc.ProgsRepo.Run(context.Background(), 1*time.Second)
	sc.MapsRepo.Run(context.Background(), 1*time.Second)
	sc.TasksRepo.Run(context.Background(), 1*time.Second)

	sc.ProgsRepo.RegisterMetrics(registry)
	sc.MapsRepo.RegisterMetrics(registry)

	resolver := &graph.Resolver{
		ProgsRepository: sc.ProgsRepo,
		MapsRepository:  sc.MapsRepo,
		TasksRepository: sc.TasksRepo,
	}

	mux := http.NewServeMux()

	srv := handler.NewDefaultServer(generated.NewExecutableSchema(generated.Config{Resolvers: resolver}))

	mux.Handle("/", playground.Handler("GraphQL playground", options.PathPrefix+"query"))
	mux.Handle("/query", srv)
	mux.Handle("/metrics", promhttp.HandlerFor(
		registry,
		promhttp.HandlerOpts{
			EnableOpenMetrics: true,
		}))

	if !options.SkipWelcome {
		log.Printf("connect to http://localhost:%s/ for GraphQL playground", port)
	}
	return http.ListenAndServe(":"+port, cors.Default().Handler(mux))
}
