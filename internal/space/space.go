// Package space implements space-level helpers: stable project references
// from git remotes, CWD -> project space resolution, capture routing, and
// space_key generation. See docs/IMPLEMENTATION.md and docs/DISTILL.md.
package space

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrNoProject is returned when the CWD is not inside a git repo with an
// origin remote.
var ErrNoProject = errors.New("no git project with an origin remote found")

// NormalizeRemoteURL canonicalizes a git remote URL so all spellings of the
// same repo produce the same string: protocol and user@ stripped, scp-like
// syntax (git@host:path) folded to host/path, trailing .git and slashes
// stripped, lowercased (git hosts are case-insensitive), e.g.
// git@github.com:Foo/Bar.git == https://github.com/foo/bar == "github.com/foo/bar".
func NormalizeRemoteURL(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:] // strip protocol
	} else if at := strings.Index(s, "@"); at >= 0 {
		// scp-like: user@host:path -> host/path
		rest := s[at+1:]
		if c := strings.Index(rest, ":"); c >= 0 {
			s = rest[:c] + "/" + rest[c+1:]
		} else {
			s = rest
		}
	}
	// strip user@ from protocol forms (ssh://git@host/...)
	if at := strings.Index(s, "@"); at >= 0 && at < strings.IndexAny(s+"/", "/") {
		s = s[at+1:]
	}
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".git")
	s = strings.TrimSuffix(s, "/")
	return strings.ToLower(s)
}

// ProjectRef is the stable project identifier: SHA-256 hex of the
// normalized git remote URL.
func ProjectRef(remoteURL string) string {
	sum := sha256.Sum256([]byte(NormalizeRemoteURL(remoteURL)))
	return hex.EncodeToString(sum[:])
}

// FindProjectRef resolves the project_ref for a working directory: walk up
// to the enclosing git repo, read remote "origin" from its config (no
// shelling out), normalize and hash.
func FindProjectRef(cwd string) (string, error) {
	url, err := RemoteOriginURL(cwd)
	if err != nil {
		return "", err
	}
	return ProjectRef(url), nil
}

// RemoteOriginURL walks up from dir to the first .git (directory or
// worktree file) and reads remote.origin.url from the git config directly.
func RemoteOriginURL(dir string) (string, error) {
	d, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	for {
		gitPath := filepath.Join(d, ".git")
		if fi, err := os.Stat(gitPath); err == nil {
			gitDir := gitPath
			if !fi.IsDir() {
				gitDir, err = resolveGitFile(gitPath)
				if err != nil {
					return "", err
				}
			}
			url, err := originFromConfig(filepath.Join(gitDir, "config"))
			if err == nil {
				return url, nil
			}
			// Worktree gitdirs keep config in the common dir.
			if common, cerr := os.ReadFile(filepath.Join(gitDir, "commondir")); cerr == nil {
				cd := strings.TrimSpace(string(common))
				if !filepath.IsAbs(cd) {
					cd = filepath.Join(gitDir, cd)
				}
				if url, err := originFromConfig(filepath.Join(cd, "config")); err == nil {
					return url, nil
				}
			}
			return "", ErrNoProject
		}
		parent := filepath.Dir(d)
		if parent == d {
			return "", ErrNoProject
		}
		d = parent
	}
}

// resolveGitFile handles a .git *file* ("gitdir: <path>"), used by worktrees
// and submodules.
func resolveGitFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	line := strings.TrimSpace(string(b))
	target, ok := strings.CutPrefix(line, "gitdir:")
	if !ok {
		return "", fmt.Errorf("%s: not a gitdir pointer", path)
	}
	target = strings.TrimSpace(target)
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	return target, nil
}

// originFromConfig parses the ini-style git config for [remote "origin"] url.
func originFromConfig(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	inOrigin := false
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			inOrigin = line == `[remote "origin"]`
			continue
		}
		if !inOrigin || line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(k) == "url" {
			return strings.TrimSpace(v), nil
		}
	}
	return "", ErrNoProject
}

// Subject classifies what a captured learning is about.
type Subject string

const (
	SubjectUser      Subject = "user"
	SubjectCodebase  Subject = "codebase"
	SubjectAmbiguous Subject = "ambiguous"
)

// RouteSpace applies the capture-routing rule: about the user -> personal;
// about the codebase -> the CWD's project space; ambiguous (or no project
// space available) -> personal, the safe side.
func RouteSpace(subject Subject, personalSpaceID, projectSpaceID string) string {
	if subject == SubjectCodebase && projectSpaceID != "" {
		return projectSpaceID
	}
	return personalSpaceID
}

// NewSpaceKey generates a fresh 32-byte symmetric space key.
func NewSpaceKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}
