package filesystem

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/anchore/syft/syft/file"
	"github.com/bmatcuk/doublestar/v4"
)

var _ file.Resolver = (*Resolver)(nil)

// Filesystem implements path and content access for files from a fs.FS
type Resolver struct {
	//filetreeResolver
	fs     fs.FS
	logger *slog.Logger
	// indexer *directoryIndexer
}

func NewResolver(iofs fs.FS) (file.Resolver, error) {
	if iofs == nil {
		return nil, fmt.Errorf("unable to create resolver, no filesystem defined")
	}
	return &Resolver{
		logger: slog.Default(),
		fs:     iofs,
	}, nil
}

func (r *Resolver) AllLocations(ctx context.Context) <-chan file.Location {
	r.logger.Info("AllLocations Invoked")
	out := make(chan file.Location)
	errWalkCanceled := fmt.Errorf("walk canceled")
	go func() {
		defer close(out)
		err := fs.WalkDir(r.fs, "/", func(p string, _ fs.DirEntry, _ error) error {
			r.logger.Info(fmt.Sprintf("walking %s", p))
			p = strings.TrimPrefix(p, "/")
			select {
			case out <- file.NewLocation(p):
				return nil
			case <-ctx.Done():
				return errWalkCanceled
			}
		})
		if err != nil && !errors.Is(err, errWalkCanceled) {
			r.logger.Debug(err.Error())
		}
	}()
	return out
}

func (r *Resolver) FileContentsByLocation(location file.Location) (io.ReadCloser, error) {
	p := r.absPath(r.scrubInputPath(location.RealPath))
	f, err := r.fs.Open(p)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if fi.IsDir() {
		return nil, fmt.Errorf("unable to get contents of directory: %s", location.RealPath)
	}
	return f, nil
}

func (r *Resolver) FileMetadataByLocation(_ file.Location) (file.Metadata, error) {
	return file.Metadata{}, errors.New("FileMetadataByLocation not implemented")
}

func (r *Resolver) FilesByGlob(patterns ...string) (out []file.Location, _ error) {
	return r.filesByGlob(true, false, patterns...)
}

func (r *Resolver) filesByGlob(resolveLinks bool, includeDirs bool, patterns ...string) (out []file.Location, _ error) {
	r.logger.Info(fmt.Sprintf("Calling filesByGlob %+v", patterns))
	var paths []string
	for _, p := range patterns {
		opts := []doublestar.GlobOption{doublestar.WithNoFollow()}
		if !includeDirs {
			opts = append(opts, doublestar.WithFilesOnly())
		}
		found, err := doublestar.Glob(r.fs, p, opts...)
		if err != nil {
			return nil, err
		}
		paths = append(paths, found...)
	}
	locations, err := r.filesByPath(resolveLinks, includeDirs, paths...)
	r.logger.Info(fmt.Sprintf("Globbing %+v returned %+v", patterns, locations))
	return locations, err
}

func (r *Resolver) FilesByPath(paths ...string) (out []file.Location, _ error) {
	return r.filesByPath(true, false, paths...)
}

func (r *Resolver) filesByPath(resolveLinks bool, includeDirs bool, paths ...string) (out []file.Location, _ error) {
	r.logger.Info(fmt.Sprintf("Calling filesByPath %+v", paths))
	sort.Strings(paths)
nextPath:
	for _, p := range paths {
		p = r.scrubInputPath(p)
		if r.canLstat(p) && (includeDirs || r.isRegularFile(p)) {
			l := r.newLocation(p, resolveLinks)
			if l == nil {
				continue
			}
			// only include the first entry we find
			for i := range out {
				existing := &out[i]
				if existing.RealPath == l.RealPath {
					if l.AccessPath == "" {
						existing.AccessPath = ""
					}
					continue nextPath
				}
			}
			out = append(out, *l)
		}
	}
	return
}

func (r *Resolver) scrubInputPath(p string) string {
	r.logger.Info("scrubbing: " + p)
	if path.IsAbs(p) {
		p = p[1:]
	}
	return path.Clean(p)
}

func (r *Resolver) newLocation(filePath string, resolveLinks bool) *file.Location {
	filePath = path.Clean(filePath)

	virtualPath := filePath
	realPath := filePath

	if resolveLinks {
		paths := r.resolveLinks(filePath)
		if len(paths) > 1 {
			realPath = paths[len(paths)-1]
			if realPath != path.Clean(filePath) {
				virtualPath = paths[0]
			}
		}
		if len(paths) == 0 {
			// this file does not exist, don't return a location
			return nil
		}
	}

	l := file.NewVirtualLocation(realPath, virtualPath)
	return &l
}

func (r *Resolver) resolveLinks(filePath string) []string {
	r.logger.Info("Trying to resolve link " + filePath)
	var visited []string

	out := []string{}

	resolvedPath := ""

	parts := strings.Split(filePath, "/")
	for i := 0; i < len(parts); i++ {
		part := parts[i]
		if resolvedPath == "" {
			resolvedPath = part
		} else {
			resolvedPath = path.Clean(path.Join(resolvedPath, part))
		}
		resolvedPath = r.scrubResolutionPath(resolvedPath)
		if resolvedPath == ".." {
			resolvedPath = ""
			continue
		}

		absPath := r.absPath(resolvedPath)
		if slices.Contains(visited, absPath) {
			return nil // circular links can't resolve
		}
		visited = append(visited, absPath)

		fi, wasLstat, err := r.LstatIfPossible(absPath)
		if fi == nil || err != nil {
			// this file does not exist
			return nil
		}

		for wasLstat && r.isSymlink(fi) {
			next, err := r.ReadlinkIfPossible(absPath)
			if err == nil {
				if !path.IsAbs(next) {
					next = path.Clean(path.Join(path.Dir(resolvedPath), next))
				}
				next = r.scrubResolutionPath(next)
				absPath = r.absPath(next)
				if slices.Contains(visited, absPath) {
					return nil // circular links can't resolve
				}
				visited = append(visited, absPath)

				fi, wasLstat, err = r.LstatIfPossible(absPath)
				if fi == nil || err != nil {
					// this file does not exist
					return nil
				}
				if i < len(parts) {
					out = append(out, path.Join(resolvedPath, path.Join(parts[i+1:]...)))
				}
				if path.IsAbs(next) {
					next = next[1:]
				}
				resolvedPath = next
			}
		}
	}

	out = append(out, resolvedPath)
	r.logger.Info(fmt.Sprintf(" > Resolved %s to %+v", filePath, out))
	return out
}

func (r *Resolver) absPath(p string) string {
	if path.IsAbs(p) {
		return p
	}

	return path.Clean(path.Join("./", p))
}

func (r *Resolver) FilesByMIMEType(_ ...string) ([]file.Location, error) {
	return nil, errors.New("FilesByMIMEType not implemented")
}

func (r *Resolver) HasPath(p string) bool {
	locs, err := r.filesByPath(true, true, p)
	return err == nil && len(locs) > 0
}

// RelativeFileByPath fetches a single file at the given path relative to the layer squash of the given reference.
// This is helpful when attempting to find a file that is in the same layer or lower as another file.
func (r *Resolver) RelativeFileByPath(l file.Location, p string) *file.Location {
	r.logger.Info("Relativefileby path")
	p = path.Clean(path.Join(l.RealPath, p))
	locs, err := r.filesByPath(true, false, p)
	if err != nil || len(locs) == 0 {
		return nil
	}
	l = locs[0]
	p = l.RealPath
	if r.isRegularFile(p) {
		return r.newLocation(p, true)
	}
	return nil
}

func (r *Resolver) isRegularFile(p string) bool {
	fi, _, err := r.LstatIfPossible(r.absPath(p))
	return err == nil && !fi.IsDir()
}

func (r *Resolver) scrubResolutionPath(p string) string {
	return path.Clean(p)
}

// FIXME
func (r *Resolver) canLstat(p string) bool {
	_, _, err := r.LstatIfPossible(r.absPath(p))
	return err == nil
}

func (r *Resolver) isSymlink(fi os.FileInfo) bool {
	return fi.Mode().Type()&fs.ModeSymlink == fs.ModeSymlink
}

func (r *Resolver) LstatIfPossible(name string) (os.FileInfo, bool, error) {
	r.logger.Info("Lstat if possible " + name)
	var (
		ret      os.FileInfo
		wasLstat bool
		err      error
	)

	if r.fs == nil {
		return nil, false, fmt.Errorf("unable to lstat, no filesystem defined")
	}

	if _, ok := r.fs.(LstatFS); ok {
		ret, err = r.fs.(LstatFS).Lstat(name)
		wasLstat = true
	} else {
		ret, err = r.fs.(fs.StatFS).Stat(name)
		wasLstat = true
	}
	r.logger.Info(fmt.Sprintf("> wasLstat: %v %+v", wasLstat, ret))
	return ret, wasLstat, err
}

func (r *Resolver) ReadlinkIfPossible(name string) (string, error) {
	if _, ok := r.fs.(ReadlinkFS); ok {
		return r.fs.(ReadlinkFS).Readlink(name)
	} else {
		return "", ErrNoReadlink
	}
}

type LstatFS interface {
	Lstat(string) (os.FileInfo, error)
}

var ErrNoReadlink = errors.New("readlink not supported")

type ReadlinkFS interface {
	Readlink(string) (string, error)
}
