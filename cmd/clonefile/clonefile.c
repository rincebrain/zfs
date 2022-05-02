/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2022 Pawel Jakub Dawidek <pawel@dawidek.net>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/module.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <err.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int sys_fclonefile;

static void
register_syscall(void)
{
	struct module_stat stat;
	int modid;

	stat.version = sizeof(stat);
	if ((modid = modfind("sys/fclonefile")) == -1)
		err(1, "modfind");
	if (modstat(modid, &stat) != 0)
		err(1, "modstat");
	sys_fclonefile = stat.data.intval;
}

static ssize_t
fclonefile(int srcfd, int dstfd)
{

	return (__syscall(sys_fclonefile, (int64_t)srcfd, (int64_t)dstfd));
}

static void
usage(const char *progname)
{

	errx(1, "usage: %s [-f] <srcfile> <dstfile>", progname);
}

int
main(int argc, char *argv[])
{
	struct stat sb;
	const char *progname, *srcfile, *dstfile;
	int srcfd, dstfd, flags;
	ssize_t done;
	bool force;

	progname = argv[0];

	if (argc == 4 && strcmp(argv[1], "-f") == 0) {
		force = true;
		argv++;
		argc--;
	} else {
		force = false;
	}
	if (argc != 3) {
		usage(progname);
	}

	srcfile = argv[1];
	dstfile = argv[2];

	register_syscall();

	srcfd = open(srcfile, O_RDONLY);
	if (srcfd < 0) {
		err(1, "open(%s) failed", srcfile);
	}

	flags = O_WRONLY | O_CREAT;
	if (force) {
		flags |= O_TRUNC;
	} else {
		flags |= O_EXCL;
	}
	dstfd = open(dstfile, flags, 0644);
	if (dstfd < 0) {
		err(1, "open(%s) failed", dstfile);
	}

	done = fclonefile(srcfd, dstfd);
	if (done < 0) {
		err(1, "fclonefile() failed");
	}
	if (fstat(srcfd, &sb) < 0) {
		err(1, "fstat(%s) failed", srcfile);
	}
	if (sb.st_size > (size_t)done) {
		warnx("file %s not fully cloned (%zd out of %zu)",
		    srcfile, done, sb.st_size);
	} else if (sb.st_size < (size_t)done) {
		warnx("file %s appears to shrunk after cloning (%zd > %zu)",
		    srcfile, done, sb.st_size);
	}

	exit(0);
}
