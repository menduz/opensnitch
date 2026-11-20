package procmon

import (
	"io/ioutil"
	"regexp"
	"strings"
)

// The slice of a sandbox: systemd makes the name of a slice from the names
// of its parents, and a sandbox name has only a-z, 0-9 and _.
var sandboxSliceRe = regexp.MustCompile(`^sandbox-([a-z0-9_]+)\.slice$`)

// SandboxOfCgroup returns the sandbox of a process from the content of
// /proc/<pid>/cgroup: the name in the first slice below sandbox.slice in
// the cgroup v2 path (the line 0::). It returns "" for a process in no
// sandbox.
func SandboxOfCgroup(cgroup string) string {
	for _, line := range strings.Split(cgroup, "\n") {
		if !strings.HasPrefix(line, "0::") {
			continue
		}
		parts := strings.Split(line[len("0::"):], "/")
		for i := 0; i+1 < len(parts); i++ {
			if parts[i] != "sandbox.slice" {
				continue
			}
			if m := sandboxSliceRe.FindStringSubmatch(parts[i+1]); m != nil {
				return m[1]
			}
			return ""
		}
	}
	return ""
}

// ReadSandbox reads the sandbox of the process from its cgroup.
func (p *Process) ReadSandbox() {
	raw, err := ioutil.ReadFile(p.pathCgroup)
	if err != nil {
		return
	}
	sandbox := SandboxOfCgroup(string(raw))
	p.mu.Lock()
	p.Sandbox = sandbox
	p.mu.Unlock()
}
