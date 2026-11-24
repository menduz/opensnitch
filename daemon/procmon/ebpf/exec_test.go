//go:build linux

package ebpf

import (
	"os"
	"testing"

	"github.com/evilsocket/opensnitch/daemon/procmon"
)

// A wrapper executes the program that it wraps with the same PID: two exec
// events for one PID, with different paths. The cache replaces the item of
// the wrapper with the program. The item of the program must have the
// details that the event does not give: the cwd, the environment and the
// sandbox. The rules use them.
func TestExecEventSamePidReadsDetails(t *testing.T) {
	pid := os.Getpid()
	procmon.EventsCache.Delete(pid)

	wrapper := procmon.NewProcessEmpty(pid, "wrapper")
	wrapper.Path = "/nix/store/00000000000000000000000000000000-wrapper/bin/wrapper"
	procmon.EventsCache.Add(wrapper)

	// The exec event of the program. event2process reads the path of the
	// program in /proc/<pid>/exe: the path of this test.
	event := &execEvent{
		Type: EV_TYPE_EXEC,
		PID:  uint32(pid),
		UID:  uint32(os.Getuid()),
		PPID: uint32(os.Getppid()),
	}
	copy(event.Comm[:], "program")
	processExecEvent(event)

	item, found := procmon.EventsCache.IsInStoreByPID(pid)
	if !found {
		t.Fatal("the PID is not in the cache")
	}
	if item.Proc.Path == wrapper.Path {
		t.Fatalf("the cache did not replace the wrapper: %s", item.Proc.Path)
	}
	if len(item.Proc.Env) == 0 {
		t.Error("the program has no environment")
	}
	if cwd, _ := os.Getwd(); item.Proc.CWD != cwd {
		t.Errorf("CWD = %q, want %q", item.Proc.CWD, cwd)
	}
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatal(err)
	}
	if want := procmon.SandboxOfCgroup(string(raw)); item.Proc.Sandbox != want {
		t.Errorf("Sandbox = %q, want %q", item.Proc.Sandbox, want)
	}
}
