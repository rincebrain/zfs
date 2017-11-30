#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Copyright (c) 2012, 2016 by Delphix. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/cli_root/zpool_create/zpool_create.shlib

#
# DESCRIPTION:
#	Verify zpool add fails when adding vdevs with mismatched redundancy
#	if it was formerly a log device.
#
# STRATEGY:
#	1. Create base filesystem to hold virtual disk files.
#	2. Create several files == $MINVDEVSIZE.
#	3. Create pool with given redundancy.
#	3. Verify 'zpool add' fails with with matching redundancy.
#

verify_runnable "global"

function cleanup
{
	datasetexists $TESTPOOL1 && destroy_pool $TESTPOOL1
	datasetexists $TESTPOOL && destroy_pool $TESTPOOL
}


log_assert "Verify 'zpool add' with a former log device fails."
log_onexit cleanup

create_pool $TESTPOOL $DISKS
mntpnt=$(get_prop mountpoint $TESTPOOL)

typeset -i i=0
while ((i < 10)); do
	log_must truncate -s $MINVDEVSIZE $mntpnt/vdev$i

	eval vdev$i=$mntpnt/vdev$i
	((i += 1))
done

set -A redundancy1_create_args \
	"mirror $vdev0 $vdev1" \
	"raidz1 $vdev0 $vdev1"

set -A redundancy2_create_args \
	"mirror $vdev0 $vdev1 $vdev2" \
	"raidz2 $vdev0 $vdev1 $vdev2"

set -A redundancy3_create_args \
	"mirror $vdev0 $vdev1 $vdev2 $vdev3" \
	"raidz3 $vdev0 $vdev1 $vdev2 $vdev3"

set -A redundancy_log_args \
	"$vdev4"

set -A redundancy1_add_args \
	"mirror $vdev5 $vdev6" \
	"raidz1 $vdev5 $vdev6" \
	"raidz1 $vdev5 $vdev6 mirror $vdev7 $vdev8" \
	"mirror $vdev5 $vdev6 raidz1 $vdev7 $vdev8"

set -A redundancy2_add_args \
	"mirror $vdev5 $vdev6 $vdev7" \
	"raidz2 $vdev5 $vdev6 $vdev7"

set -A redundancy3_add_args \
	"mirror $vdev5 $vdev6 $vdev7 $vdev8" \
	"raidz3 $vdev5 $vdev6 $vdev7 $vdev8"

typeset -i j=0

function zpool_create_remove_add
{
	typeset -n create_args=$1
	typeset -n log_args=$2
	typeset -n add_args=$3

	i=0
	while ((i < ${#create_args[@]})); do
		j=0
		while ((j < ${#log_args[@]})); do
			k=0
			while ((k < ${#add_args[@]})); do
				log_must zpool create $TESTPOOL1 ${create_args[$i]}
				log_must zpool add $TESTPOOL1 log ${log_args[$j]}
				log_must zpool add $TESTPOOL1 ${add_args[$k]}
				log_must zpool remove $TESTPOOL1 ${log_args[$j]}
				log_mustnot zpool add $TESTPOOL1 log ${log_args[$j]}
				log_must zpool destroy -f $TESTPOOL1
				((k += 1))
			done
			((j += 1))
		done
		((i += 1))
	done
}

zpool_create_remove_add redundancy0_create_args redundancy_log_args redundancy0_add_args
zpool_create_remove_add redundancy1_create_args redundancy_log_args redundancy1_add_args
zpool_create_remove_add redundancy2_create_args redundancy_log_args redundancy2_add_args
zpool_create_remove_add redundancy3_create_args redundancy_log_args redundancy3_add_args

log_pass "'zpool add' failed with former log device."
