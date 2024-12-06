package filesystem

import (
	"fmt"
	"io/fs"
	"sync"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/google/uuid"
)

var _ source.Source = (*Source)(nil)

/*
type Source interface {
	artifact.Identifiable
	FileResolver(Scope) (file.Resolver, error)
	Describe() Description
	io.Closer
}
*/

type Source struct {
	id       artifact.ID
	config   Config
	mutex    *sync.Mutex
	resolver file.Resolver
}

type Config struct {
	Name    string
	Exclude source.ExcludeConfig
	Alias   source.Alias
	FS      fs.FS
}

func NewSource(cfg Config) (source.Source, error) {
	return &Source{
		id:     artifact.ID(uuid.New().String()),
		config: cfg,
		mutex:  &sync.Mutex{},
	}, nil
}

func (s Source) Describe() source.Description {
	name := s.config.Name
	version := ""

	if !s.config.Alias.IsEmpty() {
		a := s.config.Alias
		if a.Name != "" {
			name = a.Name
		}
		if a.Version != "" {
			version = a.Version
		}
	}
	return source.Description{
		ID:      string(s.id),
		Name:    name,
		Version: version,
	}
}

func (s *Source) FileResolver(_ source.Scope) (file.Resolver, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.resolver == nil {
		res, err := NewResolver(s.config.FS)
		if err != nil {
			return nil, fmt.Errorf("unable to create resolver: %w", err)
		}

		s.resolver = res
	}

	return s.resolver, nil
}

func (s *Source) Close() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Dealocate the FS resolver
	s.resolver = nil
	return nil
}

func (s Source) ID() artifact.ID {
	return s.id
}
