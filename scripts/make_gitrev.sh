#!/bin/sh

#
# CDDL HEADER START
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#
# CDDL HEADER END
#

# Copyright (c) 2018 by Delphix. All rights reserved.
# Copyright (c) 2018 by Matthew Thode. All rights reserved.

#
# Generate zfs_gitrev.h.  Note that we need to do this for every
# invocation of `make`, including for incremental builds.  Therefore we
# can't use a zfs_gitrev.h.in file which would be processed only when
# `configure` is run.
#

set -e -u

dist=no
distdir=.
while getopts D: flag
do
	case $flag in
		\?) echo "Usage: $0 [-D distdir] [file]" >&2; exit 1;;
		D)  dist=yes; distdir=${OPTARG};;
	esac
done
shift $((OPTIND - 1))

top_srcdir="$(dirname "$0")/.."
GITREV="${1:-include/zfs_gitrev.h}"

# GITREV should be a relative path (relative to top_builddir or distdir)
case "${GITREV}" in
	/*) echo "Error: ${GITREV} should be a relative path" >&2
	    exit 1;;
esac

ZFS_GITREV=$({ cd "${top_srcdir}" &&
	git describe --always --long --dirty 2>/dev/null; } || :)

if [ -z "${ZFS_GITREV}" ]
then
	# If the source directory is not a git repository, check if the file
	# already exists (in the source)
	if [ -f "${top_srcdir}/${GITREV}" ]
	then
		ZFS_GITREV=$(sed -n \
			'1s/^#define[[:blank:]]ZFS_META_GITREV "\([^"]*\)"$/\1/p' \
			"${top_srcdir}/${GITREV}")
	fi
elif [ ${dist} = yes ]
then
	# Append -dist when creating distributed sources from a git repository
	ZFS_GITREV="${ZFS_GITREV}-dist"
fi
ZFS_GITREV=${ZFS_GITREV:-unknown}
META_VER=$(sed -n 's/^Version\:[[:blank:]]*\([0-9]\+\.[0-9]\+\.[0-9]\+\)/\1/p' "${top_srcdir}/META")

if [ "${ZFS_GITREV}" = "unknown" ]
then
	echo "Warning: GITREV is unknown, this probably means your tarball was generated incorrectly."
	echo "Please report a bug at https://github.com/openzfs/zfs/issues/new/choose"
elif [ "$(echo $ZFS_GITREV | grep ${META_VER} | wc -c)" = "0" ]
then
	# Let's not break on CI runs, shall we?
	if [ "$(echo $ZFS_GITREV | egrep '^[0-9a-f]{7}(-dist)?$' | wc -c)" = "0" ]
	then
		echo "Error: GITREV (${ZFS_GITREV}) does not contain the Version from META (${META_VER});" \
		    "this probably means your git tree is mangled. Please recreate your branch and try again."
		exit 1
	fi
fi

GITREVTMP="${GITREV}~"
printf '#define\tZFS_META_GITREV "%s"\n' "${ZFS_GITREV}" >"${GITREVTMP}"
GITREV="${distdir}/${GITREV}"
if cmp -s "${GITREV}" "${GITREVTMP}"
then
	rm -f "${GITREVTMP}"
else
	mv -f "${GITREVTMP}" "${GITREV}"
fi
