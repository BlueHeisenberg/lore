package space

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeRemoteURLMatrix(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://github.com/foo/bar", "github.com/foo/bar"},
		{"https://github.com/Foo/Bar.git", "github.com/foo/bar"},
		{"http://github.com/foo/bar.git", "github.com/foo/bar"},
		{"git@github.com:Foo/Bar.git", "github.com/foo/bar"},
		{"git@github.com:foo/bar", "github.com/foo/bar"},
		{"ssh://git@github.com/foo/bar.git", "github.com/foo/bar"},
		{"git://github.com/foo/bar.git", "github.com/foo/bar"},
		{"https://user@github.com/foo/bar.git", "github.com/foo/bar"},
		{"https://GitHub.COM/foo/bar/", "github.com/foo/bar"},
		{"  git@github.com:foo/bar.git \n", "github.com/foo/bar"},
		{"git@gitlab.example.com:group/sub/repo.git", "gitlab.example.com/group/sub/repo"},
	}
	for _, c := range cases {
		if got := NormalizeRemoteURL(c.in); got != c.want {
			t.Errorf("NormalizeRemoteURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// The equivalence the contract calls out, as refs:
	if ProjectRef("git@github.com:Foo/Bar.git") != ProjectRef("https://github.com/foo/bar") {
		t.Fatal("scp and https spellings must produce the same project_ref")
	}
	if ProjectRef("github.com/foo/bar") == ProjectRef("github.com/foo/baz") {
		t.Fatal("different repos collided")
	}
	if len(ProjectRef("github.com/foo/bar")) != 64 {
		t.Fatal("project_ref must be sha256 hex")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const gitConfig = `[core]
	repositoryformatversion = 0
	bare = false
[remote "origin"]
	url = git@github.com:BlueHeisenberg/Lore.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
`

func TestResolveProjectFromCWD(t *testing.T) {
	repo := t.TempDir()
	writeFile(t, filepath.Join(repo, ".git", "config"), gitConfig)
	nested := filepath.Join(repo, "internal", "deep", "pkg")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}

	url, err := RemoteOriginURL(nested)
	if err != nil {
		t.Fatal(err)
	}
	if url != "git@github.com:BlueHeisenberg/Lore.git" {
		t.Fatalf("origin url = %q", url)
	}
	ref, err := FindProjectRef(nested)
	if err != nil {
		t.Fatal(err)
	}
	if ref != ProjectRef("https://github.com/blueheisenberg/lore") {
		t.Fatal("ref does not match normalized equivalent")
	}

	// Worktree-style .git file.
	wt := t.TempDir()
	gitdir := filepath.Join(repo, ".git")
	writeFile(t, filepath.Join(wt, ".git"), "gitdir: "+gitdir+"\n")
	ref2, err := FindProjectRef(wt)
	if err != nil {
		t.Fatal(err)
	}
	if ref2 != ref {
		t.Fatal("worktree ref differs from repo ref")
	}

	// No repo at all.
	if _, err := FindProjectRef(t.TempDir()); err != ErrNoProject {
		t.Fatalf("want ErrNoProject, got %v", err)
	}
}

func TestRouting(t *testing.T) {
	const personal, project = "personal-id", "project-id"
	cases := []struct {
		subject Subject
		project string
		want    string
	}{
		{SubjectUser, project, personal},
		{SubjectCodebase, project, project},
		{SubjectAmbiguous, project, personal},
		{SubjectCodebase, "", personal}, // no project space -> safe side
		{Subject("weird"), project, personal},
	}
	for _, c := range cases {
		if got := RouteSpace(c.subject, personal, c.project); got != c.want {
			t.Errorf("RouteSpace(%q, project=%q) = %q, want %q", c.subject, c.project, got, c.want)
		}
	}
}

func TestNewSpaceKey(t *testing.T) {
	a, err := NewSpaceKey()
	if err != nil || len(a) != 32 {
		t.Fatalf("key: %v len=%d", err, len(a))
	}
	b, _ := NewSpaceKey()
	if string(a) == string(b) {
		t.Fatal("space keys not random")
	}
}
