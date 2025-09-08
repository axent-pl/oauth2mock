package utils

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

var (
	ErrOutsideBase  = errors.New("path resolves outside of base directory")
	ErrBadExtension = errors.New("file has a disallowed extension")
	ErrSymlink      = errors.New("path resolves through a symlink")
	ErrBadPerms     = errors.New("file permissions too permissive")
)

// maxBytes = 10<<20 // 10 MB
func ReadFileWithin(baseDir, path string, allowedExts []string, requireStrictPerms bool, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 10 << 20 // default 10 MiB
	}

	f, err := OpenReadWithin(baseDir, path, allowedExts, requireStrictPerms)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Hard cap read size.
	lr := io.LimitReader(f, maxBytes+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file too large: over %d bytes", maxBytes)
	}
	return data, nil
}

func OpenReadWithin(baseDir, path string, allowedExts []string, requireStrictPerms bool) (*os.File, error) {
	if path == "" {
		return nil, errors.New("empty path")
	}
	if filepath.IsAbs(path) {
		return nil, fmt.Errorf("absolute paths not allowed: %s", path)
	}

	// Clean and join under the sandbox.
	clean := filepath.Clean(path)
	full := filepath.Join(baseDir, clean)

	// Resolve base and final path symlinks.
	baseResolved, err := filepath.EvalSymlinks(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve base: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	// Must remain inside baseResolved.
	rel, err := filepath.Rel(baseResolved, resolved)
	if err != nil || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
		return nil, ErrOutsideBase
	}

	// Disallow the final node being a symlink.
	fi, err := os.Lstat(resolved)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return nil, ErrSymlink
	}

	// Optional: enforce extension allowlist.
	if len(allowedExts) > 0 {
		ok := false
		ext := strings.ToLower(filepath.Ext(resolved))
		for _, a := range allowedExts {
			if ext == strings.ToLower(a) {
				ok = true
				break
			}
		}
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrBadExtension, ext)
		}
	}

	// Open read-only, no create/trunc.
	f, err := openNoFollow(resolved)
	if err != nil {
		return nil, err
	}

	// Optional: enforce strict perms (e.g., for private keys).
	if requireStrictPerms {
		if stat, err := f.Stat(); err == nil {
			// Policy: <=0600
			if perm := stat.Mode().Perm(); perm&0o077 != 0 {
				_ = f.Close()
				return nil, fmt.Errorf("%w: got %o, want 0600 or stricter", ErrBadPerms, perm)
			}
		}
	}

	return f, nil
}

func openNoFollow(resolved string) (*os.File, error) {
	// Open the parent dir as an *AT base.
	dir := filepath.Dir(resolved)
	base := filepath.Base(resolved)

	dirfd, err := unix.Open(dir, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirfd)

	fd, err := unix.Openat(dirfd, base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), resolved), nil
}
