package graph

import (
	"github.com/ebpfdev/dev-agent/pkg/ebpf/maps"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/progs"
)

//go:generate rm -f generated/generated.go
//go:generate go run github.com/99designs/gqlgen generate

// This file will not be regenerated automatically.
//
// It serves as dependency injection for your app, add any dependencies you require here.

type Resolver struct {
	ProgsRepository progs.ProgWatcher
	MapsRepository  maps.MapsWatcher
}
