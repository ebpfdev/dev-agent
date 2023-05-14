package graph

// This file will be automatically regenerated based on the schema, any resolver implementations
// will be copied through when generating and any unknown code will be moved to the end.
// Code generated by github.com/99designs/gqlgen version v0.17.31

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/ebpfdev/dev-agent/pkg/ebpf/maps"
	"github.com/ebpfdev/dev-agent/pkg/graph/generated"
	"github.com/ebpfdev/dev-agent/pkg/graph/model"
)

// Maps is the resolver for the maps field.
func (r *programResolver) Maps(ctx context.Context, obj *model.Program) ([]*model.Map, error) {
	goodMaps := make(map[ebpf.MapID]*maps.MapInfo, 0)
	for _, info := range r.MapsRepository.GetMaps() {
		goodMaps[info.ID] = info
	}

	mapsResult := obj.Maps
	for i, m := range mapsResult {
		if goodMap, ok := goodMaps[ebpf.MapID(m.ID)]; ok {
			mapsResult[i] = mapInfoToModel(goodMap)
		} else {
			errMsg := fmt.Sprintf("map with ID %d not found", m.ID)
			mapsResult[i] = &model.Map{
				ID:    m.ID,
				Error: &errMsg,
			}
		}
	}
	return mapsResult, nil
}

// Programs is the resolver for the programs field.
func (r *queryResolver) Programs(ctx context.Context) ([]*model.Program, error) {
	progs := r.ProgsRepository.GetProgs()
	result := make([]*model.Program, len(progs))
	for i, prog := range progs {
		result[i] = progInfoToModel(&prog)
	}
	return result, nil
}

// Maps is the resolver for the maps field.
func (r *queryResolver) Maps(ctx context.Context) ([]*model.Map, error) {
	emaps := r.MapsRepository.GetMaps()
	result := make([]*model.Map, len(emaps))
	for i, m := range emaps {
		result[i] = mapInfoToModel(m)
	}
	return result, nil
}

// Program returns generated.ProgramResolver implementation.
func (r *Resolver) Program() generated.ProgramResolver { return &programResolver{r} }

// Query returns generated.QueryResolver implementation.
func (r *Resolver) Query() generated.QueryResolver { return &queryResolver{r} }

type programResolver struct{ *Resolver }
type queryResolver struct{ *Resolver }
