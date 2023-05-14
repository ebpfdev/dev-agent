package commands

import (
	"context"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/maps"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/progs"
	"github.com/ebpfdev/dev-agent/pkg/graph"
	"github.com/ebpfdev/dev-agent/pkg/graph/generated"
	"log"
	"net/http"
	"os"
)

type ServerCommands struct {
	MapsRepo  maps.MapsWatcher
	ProgsRepo progs.ProgWatcher
}

const defaultPort = "8080"

func (sc *ServerCommands) ServerStart() error {

	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	sc.ProgsRepo.Run(context.Background())
	sc.MapsRepo.Run(context.Background())

	resolver := &graph.Resolver{
		ProgsRepository: sc.ProgsRepo,
		MapsRepository:  sc.MapsRepo,
	}

	srv := handler.NewDefaultServer(generated.NewExecutableSchema(generated.Config{Resolvers: resolver}))

	http.Handle("/", playground.Handler("GraphQL playground", "/query"))
	http.Handle("/query", srv)

	log.Printf("connect to http://localhost:%s/ for GraphQL playground", port)
	return http.ListenAndServe(":"+port, nil)
}