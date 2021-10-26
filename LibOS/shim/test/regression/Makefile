include ../../../../Scripts/Makefile.configs

# Disable implicit rules so that Make doesn't try to compile the binaries
.SUFFIXES:

GRAMINE_PKGLIBDIR ?= $(shell python3 -c 'import graminelibos; print(graminelibos._CONFIG_PKGLIBDIR)')
BINARY_DIR = $(GRAMINE_PKGLIBDIR)/tests/libos/regression

c_executables-x86_64 = \
	cpuid \
	debug_regs-x86_64 \
	rdtsc \
	sighandler_divbyzero

ifeq ($(SGX),1)
	c_executables-x86_64 += attestation
endif

c_executables = \
	abort \
	abort_multithread \
	bootstrap \
	bootstrap_pie \
	bootstrap_static \
	debug \
	devfs \
	device_passthrough \
	double_fork \
	epoll_epollet \
	epoll_wait_timeout \
	eventfd \
	exec \
	exec_fork \
	exec_invalid_args \
	exec_same \
	exec_victim \
	exit \
	exit_group \
	fcntl_lock \
	fdleak \
	file_check_policy \
	file_size \
	fopen_cornercases \
	fork_and_exec \
	fp_multithread \
	fstat_cwd \
	futex_bitset \
	futex_requeue \
	futex_timeout \
	futex_wake_op \
	getcwd \
	getdents \
	getdents_lseek \
	getsockname \
	getsockopt \
	gettimeofday \
	groups \
	helloworld \
	host_root_fs \
	init_fail \
	kill_all \
	large_dir_read \
	large_file \
	large_mmap \
	madvise \
	mkfifo \
	mmap_file \
	mprotect_file_fork \
	mprotect_prot_growsdown \
	multi_pthread \
	openmp \
	pipe \
	pipe_nonblocking \
	pipe_ocloexec \
	poll \
	poll_closed_fd \
	poll_many_types \
	ppoll \
	proc_common \
	proc_cpuinfo \
	proc_path \
	pselect \
	pthread_set_get_affinity \
	readdir \
	rename_unlink \
	run_test \
	sched \
	sched_set_get_affinity \
	sealed_file \
	sealed_file_mod \
	select \
	send_handle \
	shared_object \
	sigaction_per_process \
	sigaltstack \
	sighandler_reset \
	sighandler_sigpipe \
	signal_multithread \
	sigprocmask_pending \
	spinlock \
	stat_invalid_args \
	syscall \
	syscall_restart \
	sysfs_common \
	tcp_ipv6_v6only \
	tcp_msg_peek \
	udp \
	uid_gid \
	unix \
	vfork_and_exec \
	$(c_executables-$(ARCH))

cxx_executables-x86_64 = bootstrap_cpp

repo_manifests = \
	argv_from_file.manifest \
	debug_log_file.manifest \
	debug_log_inline.manifest \
	device_passthrough.manifest \
	env_from_file.manifest \
	env_from_host.manifest \
	env_passthrough.manifest \
	file_check_policy_allow_all_but_log.manifest \
	file_check_policy_strict.manifest \
	multi_pthread_exitless.manifest

gen_manifests = $(addsuffix .manifest,$(c_executables) $(cxx_executables-$(ARCH)))
all_manifests = $(repo_manifests) $(gen_manifests)

target = $(all_manifests)

clean-extra += clean-tmp

# Variables passed to `gramine-manifest`
extra_rules = \
	-Dra_client_spid=$(if $(RA_CLIENT_SPID),$(RA_CLIENT_SPID),) \
	-Dra_client_linkable=$(if $(RA_CLIENT_LINKABLE),$(RA_CLIENT_LINKABLE),0) \
	-Dbinary_dir=$(BINARY_DIR)

include ../../../../Scripts/manifest.mk
include ../../../../Scripts/Makefile.Test

.PHONY: regression
regression: $(target)
	$(RM) libos-regression.xml
	$(MAKE) libos-regression.xml

libos-regression.xml: test_libos.py $(call expand_target_to_token,$(target))
	../../../../Scripts/run-pytest --junit-xml $@ -v $<

.PHONY: clean-tmp
clean-tmp:
	$(RM) -r \
		*.dat \
		*.manifest \
		*.manifest.sgx \
		*.sig \
		*.token \
		.pytest_cache \
		__pycache__ \
		*.xml \
		testfile \
		trusted_testfile \
		tmp/*
