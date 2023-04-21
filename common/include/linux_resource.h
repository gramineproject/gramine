/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2023 Fortanix Inc
 *                    Nirjhar Roy <nirjhar.roy@fortanix.com> */

#pragma once

#define GRAMINE_RUSAGE_SELF 0
#define GRAMINE_RUSAGE_CHILDREN -1
#define GRAMINE_RUSAGE_THREAD 1

struct gramine_timeval {
  long tv_sec;		/* Seconds.  */
  long tv_usec;	/* Microseconds.  */
};

struct gramine_rusage {
    /* Total amount of user time used.  */
    struct gramine_timeval ru_utime;
    /* Total amount of system time used.  */
    struct gramine_timeval ru_stime;
    /* Maximum resident set size (in kilobytes).  */
	long int ru_maxrss;
    /* Amount of sharing of text segment memory
       with other processes (kilobyte-seconds).  */
	long int ru_ixrss;
    /* Amount of data segment memory used (kilobyte-seconds).  */
	long int ru_idrss;
    /* Amount of stack memory used (kilobyte-seconds).  */
	long int ru_isrss;
    /* Number of soft page faults (i.e. those serviced by reclaiming
       a page from the list of pages awaiting reallocation.  */
	long int ru_minflt;
    /* Number of hard page faults (i.e. those that required I/O).  */
	long int ru_majflt;
    /* Number of times a process was swapped out of physical memory.  */
	long int ru_nswap;
    /* Number of input operations via the file system.  Note: This
     *  and `ru_oublock' do not include operations with the cache.  */
	long int ru_inblock;
    /* Number of output operations via the file system.  */
	long int ru_oublock;
    /* Number of IPC messages sent.  */
	long int ru_msgsnd;
    /* Number of IPC messages received.  */
	long int ru_msgrcv;
    /* Number of signals delivered.  */
	long int ru_nsignals;
    /* Number of voluntary context switches, i.e. because the process
     * gave up the process before it had to (usually to wait for some
     *  resource to be available).  */
	long int ru_nvcsw;
    /* Number of involuntary context switches, i.e. a higher priority process
       became runnable or the current process used up its time slice.  */
	long int ru_nivcsw;
};
