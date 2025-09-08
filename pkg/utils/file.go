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

// OpenCreateWithin safely CREATES a NEW file (fails if it exists) under baseDir,
// refusing to follow symlinks. The resulting file is created with perm (default 0600).
// This is the safe counterpart to:
//
//	os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
func OpenCreateWithin(baseDir, path string, allowedExts []string, perm fs.FileMode) (*os.File, error) {
	if perm == 0 {
		perm = 0o600
	}
	if path == "" {
		return nil, errors.New("empty path")
	}
	if filepath.IsAbs(path) {
		return nil, fmt.Errorf("absolute paths not allowed: %s", path)
	}

	clean := filepath.Clean(path)
	full := filepath.Join(baseDir, clean)

	baseResolved, err := filepath.EvalSymlinks(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve base: %w", err)
	}

	// We resolve symlinks for the PARENT directory only, since the file may not exist yet.
	parent := filepath.Dir(full)
	baseName := filepath.Base(full)

	parentResolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve parent dir: %w", err)
	}

	// Must remain inside baseResolved.
	rel, err := filepath.Rel(baseResolved, parentResolved)
	if err != nil || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
		return nil, ErrOutsideBase
	}

	// Optional: enforce extension allowlist.
	if len(allowedExts) > 0 {
		ok := false
		ext := strings.ToLower(filepath.Ext(baseName))
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

	// Open the parent dir and then openat with O_CREAT|O_EXCL|O_NOFOLLOW to avoid races/symlinks.
	dirfd, err := unix.Open(parentResolved, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirfd)

	flags := unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_CLOEXEC | unix.O_NOFOLLOW
	// #nosec G304 -- path is validated (cleaned, confined to base, parent resolved) and opened via openat+O_NOFOLLOW.
	fd, err := unix.Openat(dirfd, baseName, flags, uint32(perm))
	if err != nil {
		return nil, err
	}

	f := os.NewFile(uintptr(fd), filepath.Join(parentResolved, baseName))

	// Enforce exact perms (umask may have interfered).
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// OpenTruncateWithin safely OPENS an EXISTING file for writing and truncates it,
// refusing to follow symlinks. It will NOT create a new file.
func OpenTruncateWithin(baseDir, path string, allowedExts []string, requireStrictPerms bool) (*os.File, error) {
	if path == "" {
		return nil, errors.New("empty path")
	}
	if filepath.IsAbs(path) {
		return nil, fmt.Errorf("absolute paths not allowed: %s", path)
	}

	clean := filepath.Clean(path)
	full := filepath.Join(baseDir, clean)

	baseResolved, err := filepath.EvalSymlinks(baseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve base: %w", err)
	}

	// Resolve symlinks for the FULL existing path so we can verify final node isn't a symlink.
	resolved, err := filepath.EvalSymlinks(full)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	rel, err := filepath.Rel(baseResolved, resolved)
	if err != nil || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || rel == ".." {
		return nil, ErrOutsideBase
	}

	// Disallow final symlink.
	if fi, err := os.Lstat(resolved); err == nil && fi.Mode()&fs.ModeSymlink != 0 {
		return nil, ErrSymlink
	}

	// Optional: extension allowlist.
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

	// Open for write+truncate without following symlinks.
	dir := filepath.Dir(resolved)
	base := filepath.Base(resolved)

	dirfd, err := unix.Open(dir, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirfd)

	flags := unix.O_WRONLY | unix.O_TRUNC | unix.O_CLOEXEC | unix.O_NOFOLLOW
	// #nosec G304 -- path is validated (cleaned, confined to base, fully resolved) and opened via openat+O_NOFOLLOW.
	fd, err := unix.Openat(dirfd, base, flags, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), resolved)

	// Optional: enforce strict perms on the destination.
	if requireStrictPerms {
		if stat, err := f.Stat(); err == nil {
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

	// #nosec G304 -- path is validated prior to this call and opened via openat+O_NOFOLLOW.
	fd, err := unix.Openat(dirfd, base, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), resolved), nil
}
