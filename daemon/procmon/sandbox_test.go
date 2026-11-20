package procmon

import "testing"

func TestSandboxOfCgroup(t *testing.T) {
	const user = "0::/user.slice/user-1000.slice/user@1000.service"
	cases := []struct {
		name, cgroup, want string
	}{
		{"a run of a sandbox", user + "/sandbox.slice/sandbox-code.slice/sandbox-code-1234-5678.scope\n", "code"},
		{"a name with _ and digits", user + "/sandbox.slice/sandbox-ai_2.slice/sandbox-ai_2-terminal-1-2.scope\n", "ai_2"},
		{"the slice itself", user + "/sandbox.slice/sandbox-web.slice\n", "web"},
		{"a child slice: the sandbox is the first slice below sandbox.slice", user + "/sandbox.slice/sandbox-a.slice/sandbox-a-b.slice/x.scope\n", "a"},
		{"a program on the host", user + "/app.slice/app-sandbox-host-1.scope\n", ""},
		{"the window manager", user + "/session.slice/kwm.service\n", ""},
		{"a sandbox slice that is not below sandbox.slice", user + "/app.slice/sandbox-code.slice/x.scope\n", ""},
		{"sandbox.slice without a sandbox below it", user + "/sandbox.slice\n", ""},
		{"a name that systemd does not make", user + "/sandbox.slice/sandbox-Code.slice/x.scope\n", ""},
		{"cgroup v1 lines and the v2 line", "12:pids:/user.slice\n1:name=systemd:/user.slice/sandbox.slice/sandbox-v1.slice\n0::" + user[3:] + "/sandbox.slice/sandbox-v2.slice/x.scope\n", "v2"},
		{"only cgroup v1", "1:name=systemd:/user.slice/sandbox.slice/sandbox-v1.slice/x.scope\n", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		if got := SandboxOfCgroup(c.cgroup); got != c.want {
			t.Errorf("%s: SandboxOfCgroup(%q) = %q, want %q", c.name, c.cgroup, got, c.want)
		}
	}
}

func TestProcSandbox(t *testing.T) {
	p := NewProcessEmpty(1234, "curl")
	p.pathCgroup = "testdata/proc-cgroup"
	p.ReadSandbox()
	if p.Sandbox != "code" {
		t.Errorf("ReadSandbox: Sandbox = %q, want \"code\"", p.Sandbox)
	}

	p = NewProcessEmpty(1235, "gone")
	p.pathCgroup = "testdata/does-not-exist"
	p.ReadSandbox()
	if p.Sandbox != "" {
		t.Errorf("ReadSandbox of a process without a cgroup file: Sandbox = %q, want \"\"", p.Sandbox)
	}
}
