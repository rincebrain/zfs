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
#ifdef __FreeBSD__
#include <sys/module.h>
#endif
#include <libnvpair.h>

#include <sys/stat.h>
#include <sys/syscall.h>

#include <sys/fs/zfs.h>
#include <libzfs_core.h>
 
#include <err.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if defined(__FreeBSD__)
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
//#elsif defined(__linux__)
#else
#if 0
typedef struct fclonefile_args {
	uint64_t srcfd;
	uint64_t dstfd;
	loff_t src_off;
	loff_t dst_off;
	ssize_t len;
} fclonefile_args_t;
#endif

static ssize_t fclonefile(int srcfd, int dstfd, ssize_t srcsz) {
	return copy_file_range(srcfd, NULL, dstfd, NULL, srcsz, 0);
	
}

#if 0
static ssize_t
fclonefile(char* srcpath, char* dstpath) {
#if 0
	fclonefile_args_t args;
	args.srcfd = srcfd;
	args.dstfd = dstfd;
	args.src_off = 0;
	args.dst_off = 0;
	args.len = 0;
#endif
        (void) libzfs_core_init();
	int err = 0;
//	fnvlist_add_int32(innvl, "srcfd", srcfd);
//	fnvlist_add_int32(innvl, "dstfd", dstfd);
	err = lzc_clonefile(srcpath,dstpath,0,0,0);
	if (err == 0) {
		printf("we did it!\n");
		return(0);
	}
	libzfs_core_fini();
	return(err);
}
#endif
#endif
static void
usage(const char *progname)
{

	errx(1, "usage: %s [-f] <srcfile> <dstfile>", progname);
}

int
main(int argc, char *argv[])
{
	struct stat sb,db;
	const char *progname, *srcfile, *dstfile;
	int srcfd, dstfd, flags;
	ssize_t done = 0;
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

#if defined(__FreeBSD__)
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
//#elsif defined(__linux__)
#else
#if 0
//	libzfs_core_init();
	char *canonsrcpath = calloc(1024,1);
	char *canondstpath = calloc(1024,1);
	char *basename = calloc(PATH_MAX, 1);
	getcwd(basename, PATH_MAX);
	if (srcfile[0] != '/') {
		strcat(canonsrcpath,basename);
		strcat(canonsrcpath,"/");
	}
	if (dstfile[0] != '/') {
		strcat(canondstpath,basename);
		strcat(canondstpath,"/");
	}
	strcat(canonsrcpath,srcfile);
	strcat(canondstpath,dstfile);
	srcfd = open(canonsrcpath, O_RDONLY);
	fprintf(stderr, "Bees?\n");
	done = fclonefile(canonsrcpath,canondstpath);
	dstfd = open(canonsrcpath, O_RDONLY);
#endif
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

	if (fstat(srcfd, &sb) < 0) {
		err(1, "fstat(%s) failed", srcfile);
	}
	fprintf(stderr, "Keys?\n");
	done = fclonefile(srcfd, dstfd, sb.st_size);

#endif
	fprintf(stderr, "Fleas?\n");
	if (done < 0) {
		err(1, "fclonefile() failed");
	} else {
		printf("We think we did the thing, with %llu (%lld) bytes\n", done, done);
	}
	
	if (fstat(srcfd, &sb) < 0) {
		err(1, "fstat(%s) failed", srcfile);
	}
	if (fstat(dstfd, &db) < 0) {
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
