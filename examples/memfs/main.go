package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
	"github.com/anchore/syft/syft/source"
	"github.com/go-git/go-billy/v5/helper/iofs"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/puerco/syft-filesystem/pkg/filesystem"
)

func main() {
	memFS, err := createMemFS()
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}

	resolver, err := getResolver(memFS)
	if err != nil {
		fmt.Fprintf(os.Stderr, err.Error())
		os.Exit(1)
	}

	cataloger := python.NewPackageCataloger(python.CatalogerConfig{
		GuessUnpinnedRequirements: true,
	})

	packages, _, err := cataloger.Catalog(context.Background(), resolver)
	if err != nil {
		fmt.Fprintf(os.Stderr, fmt.Errorf("scanning for packages: %w", err).Error())
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(packages)
}

func getResolver(iofs fs.FS) (file.Resolver, error) {
	src, err := filesystem.NewSource(filesystem.Config{
		Name: "test",
		FS:   iofs,
	})
	if err != nil {
		return nil, fmt.Errorf("creating filesystem source: %w", err)
	}

	// resolver, err := src.FileResolver(source.SquashedScope)
	resolver, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		return nil, fmt.Errorf("creating filesystem resolver: %w", err)
	}

	return resolver, nil
}

func createMemFS() (fs.FS, error) {
	memFS := memfs.New()
	f, err := memFS.Create("requirements.txt")
	if err != nil {
		return nil, err
	}

	if _, err = f.Write([]byte("Flask==1\nrequestts==1\n")); err != nil {
		return nil, err
	}

	if err := f.Close(); err != nil {
		return nil, err
	}
	return iofs.New(memFS), nil
}
