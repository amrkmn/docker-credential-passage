package passage

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// findGitDir walks up from base to find the git working tree root.
// Mirrors passage's set_git() — returns empty string if no repo found.
func findGitDir(base string) string {
	dir := base
	for {
		if info, err := os.Stat(filepath.Join(dir, ".git")); err == nil && info.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir || !strings.HasPrefix(parent, getPassageDirStatic()+string(filepath.Separator)) {
			break
		}
		dir = parent
	}
	return ""
}

// gitAddFile stages a file and commits it with the given message.
// If no git repo is found, returns nil silently (mirrors passage: [[ -n $INNER_GIT_DIR ]] || return).
func gitAddFile(path, msg string) {
	wd := findGitDir(filepath.Dir(path))
	if wd == "" {
		return
	}
	gitCmd("add", path) // ponytail: ignore add errors — file may be outside repo
	gitCmd("commit", "-m", msg)
}

// gitAddDir stages a path (recursive) and commits with the given message.
func gitAddDir(path, msg string) {
	wd := findGitDir(path)
	if wd == "" {
		return
	}
	gitCmd("add", path)
	gitCmd("commit", "-m", msg)
}

func gitCmd(args ...string) {
	cmd := exec.Command("git", args...)
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"GIT_DIR=", "GIT_WORK_TREE=", "GIT_NAMESPACE=",
		"GIT_INDEX_FILE=", "GIT_INDEX_VERSION=",
		"GIT_OBJECT_DIRECTORY=", "GIT_COMMON_DIR=",
	)
	_ = cmd.Run()
}
