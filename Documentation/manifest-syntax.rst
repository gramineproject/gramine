Manifest syntax
===============

..
   TODO: We would like to change the below to `.. highlight:: toml`. However,
   Pygments (as of 2.11.2) fails to parse constructions such as unquoted
   `[true|false]` (because of the `|` character inside).

.. highlight:: text

A |~| manifest file is an application-specific configuration text file that
specifies the environment and resources for running an application inside
Gramine. A |~| manifest file contains key-value pairs (as well as more
complicated table and array objects) in the TOML syntax. For the details of the
TOML syntax, see `the official documentation <https://toml.io>`__.

A typical string entry looks like this::

   [Key][.Key][.Key] = "[Value]"

A typical integer entry looks similar to the above but without double quotes::

   [Key][.Key][.Key] = [Value]

Comments can be inlined in a |~| manifest by starting them with a |~| hash sign
(``# comment...``).

There is also a |~| preprocessor available: :ref:`gramine-manifest
<gramine-manifest>`, which renders manifests from Jinja templates.

Common syntax
-------------

Log level
^^^^^^^^^

::

    loader.log_level = "[none|error|warning|debug|trace|all]"
    (Default: "error")

    loader.log_file = "[PATH]"

This configures Gramine's debug log. The ``log_level`` option specifies what
messages to enable (e.g. ``loader.log_level = "debug"`` will enable all messages
of type ``error``, ``warning`` and ``debug``). By default, the messages are printed
to the standard error. If ``log_file`` is specified, the messages will be
appended to that file.

Gramine outputs log messages of the following types:

* ``error``: A serious error preventing Gramine from operating properly (for
  example, error initializing one of the components).

* ``warning``: A non-fatal issue. Might mean that application is requesting
  something unsupported or poorly emulated.

* ``debug``: Detailed information about Gramine's operation and internals.

* ``trace``: More detailed information, such as all system calls requested by
  the application. Might contain a lot of noise.

.. warning::
   Only ``error`` log level is suitable for production. Other levels may leak
   sensitive data.

Loader entrypoint
^^^^^^^^^^^^^^^^^

::

   loader.entrypoint = "[URI]"

This specifies the LibOS component that Gramine will load and run before loading
the first executable of the user application. Currently, there is only one LibOS
implementation: ``libsysdb.so``.

Note that the loader (the PAL binary) loads the LibOS binary specified in
``loader.entrypoint`` and passes control to this binary. Next, the LibOS binary
loads the actual executable (the user application) specified in
``libos.entrypoint``. Also note that, in contrast to ``libos.entrypoint``, the
``loader.entrypoint`` option specifies a PAL URI (with the ``file:`` prefix).

LibOS Entrypoint
^^^^^^^^^^^^^^^^

::

   libos.entrypoint = "[PATH]"

This specifies the first executable of the user application which is to be
started when spawning a Gramine instance from this manifest file. Needs to be a
path inside Gramine pointing to a mounted file. Relative paths will be
interpreted as starting from the current working directory (i.e. from ``/`` by
default, or ``fs.start_dir`` if specified).

The recommended usage is to provide an absolute path of the executable. This
executable must also be in the Gramine's filesystem, either directly mounted or
within a directory that is mounted. For example, if one wishes to execute the
Python 3.8 interpreter, one would specify it as the entrypoint and mount the
Python executable at the expected path within the Gramine filesystem::

   libos.entrypoint = "/usr/bin/python3.8"

   fs.mounts = [
     { path = "/usr/bin/python3.8", uri = "file:/usr/bin/python3.8" },
     # Or, if using a binary from your local directory:
     # { path = "/usr/bin/python3.8", uri = "file:python3.8" },
   ]

Command-line arguments
^^^^^^^^^^^^^^^^^^^^^^

::

   loader.insecure__use_cmdline_argv = true

or

::

   loader.argv = ["arg0", "arg1", "arg2", ...]

or

::

   loader.argv_src_file = "file:file_with_serialized_argv"

If you want your application to use commandline arguments, you must choose one
of the three mutually exclusive options:

- set ``loader.insecure__use_cmdline_argv`` (insecure in almost all cases),
- put commandline arguments into ``loader.argv`` array (note that the first
  argument is typically the program name and the actual arguments start with
  the second array item; see `this link
  <https://unix.stackexchange.com/questions/315812>`__ for an explanation),
- point ``loader.argv_src_file`` to a file
  containing output of :ref:`gramine-argv-serializer<gramine-argv-serializer>`.

If none of the above arguments-handling manifest options is specified in the
manifest, the application will get ``argv = [ <libos.entrypoint value> ]``.

``loader.argv_src_file`` is intended to point to either a trusted file or an
encrypted file. The former allows to securely hardcode arguments, the latter
allows the arguments to be provided at runtime from an external (trusted)
source.

.. note ::
   Pointing to an encrypted file is currently not supported, due to the fact
   that encryption key provisioning currently happens after setting up
   arguments.

Domain names configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sys.enable_extra_runtime_domain_names_conf = [true|false]
    (Default: false)

This option will generate the following extra configuration:

- Hostname (obtained by apps via `nodename` field in `uname` syscall),
  set to the host's hostname at initialization.
- Pseudo-file ``/etc/resolv.conf``, with keywords:

   - ``nameserver``
   - ``search``
   - ``options`` [``edns0``] [``inet6``] [``rotate``] [``use-vc``]

  Unsupported keywords and malformed lines from ``/etc/resolv.conf`` are ignored.

The functionality is achieved by taking the host's configuration via various
APIs and reading the host's configuration files. In the case of Linux PAL,
most information comes from the host's ``/etc``. The gathered information is
used to create ``/etc`` files inside Gramine's filesystem, or change Gramine
process configuration. For security-enforcing modes (such as SGX), Gramine
additionally sanitizes the information gathered from the host. Invalid host's
configuration is reported as an error (e.g. invalid hostname, or invalid IPv4
address in ``nameserver`` keyword).

Note that Gramine supports only a subset of the configuration.
Refer to the list of supported keywords.

This option takes precedence over ``fs.mounts``.
This means that etc files provided via ``fs.mounts`` will be overridden with
the ones added via this option.

Environment variables
^^^^^^^^^^^^^^^^^^^^^

::

   loader.insecure__use_host_env = [true|false]

By default, environment variables from the host will *not* be passed to the app.
This can be overridden by the option above, but most applications and runtime
libraries trust their environment variables and are completely insecure when
these are attacker-controlled. For example, an attacker can execute an
additional dynamic library by specifying ``LD_PRELOAD`` variable.

To securely set up the execution environment for an app you should use one or
both of the following options:

::

   loader.env.[ENVIRON] = "[VALUE]"
   or
   loader.env.[ENVIRON] = { value = "[VALUE]" }
   or
   loader.env.[ENVIRON] = { passthrough = true }

   loader.env_src_file = "file:file_with_serialized_envs"

``loader.env.[ENVIRON]`` adds/overwrites/passes a single environment variable
and can be used multiple times to specify more than one variable. To
add/overwrite the environment variable, specify a TOML string (``"[VALUE]"``) or
a TOML table with the key-value pair ``{ value = "[VALUE]" }``. To pass the
environment variable from the host, specify a TOML table with the key-value pair
``{ passthrough = true }``. If you specify a variable, it needs to either have a
value or be a passthrough.

``loader.env_src_file`` allows to specify a URI to a file containing serialized
environment, which can be generated using
:ref:`gramine-argv-serializer<gramine-argv-serializer>`. This option is intended
to point to either a trusted file or an encrypted file. The former allows to
securely hardcode environments (in a more flexible way than
``loader.env.[ENVIRON]`` option), the latter allows the environments to be
provided at runtime from an external (trusted) source.

.. note ::
   Pointing to an encrypted file is currently not supported, due to the fact
   that encryption key provisioning currently happens after setting up
   environment variables.

If the same variable is set in both, then ``loader.env.[ENVIRON]`` takes
precedence. It is prohibited to specify both ``value`` and ``passthrough`` keys
for the same environment variable. If manifest option ``insecure__use_host_env``
is specified, then ``passthrough = true`` manifest options have no effect (they
are "consumed" by ``insecure__use_host_env``).

.. note ::
   It is tempting to try to passthrough all environment variables using
   ``insecure__use_host_env`` and then disallow some of them using ``passthrough
   = false``. However, this deny list approach is intentionally prohibited
   because it's inherently insecure (doesn't provide any real security).
   Gramine loudly fails if ``passthrough = false`` manifest options are set.

User ID and Group ID
^^^^^^^^^^^^^^^^^^^^

::

   loader.uid = [NUM]
   loader.gid = [NUM]
   (Default: 0)

This specifies the initial, Gramine emulated user/group ID and effective
user/group ID. It must be non-negative. By default, Gramine emulates the
user/group ID and effective user/group ID as the root user (uid = gid = 0).


Disabling ASLR
^^^^^^^^^^^^^^

::

    loader.insecure__disable_aslr = [true|false]
    (Default: false)

This specifies whether to disable Address Space Layout Randomization (ASLR).
Since disabling ASLR worsens security of the application, ASLR is enabled by
default.

Check invalid pointers
^^^^^^^^^^^^^^^^^^^^^^

::

    libos.check_invalid_pointers = [true|false]
    (Default: true)

This specifies whether to enable checks of invalid pointers on syscall
invocations. In particular, when this manifest option is set to ``true``,
Gramine's LibOS will return an EFAULT error code if a user-supplied buffer
points to an invalid memory region. Setting this manifest option to ``false``
may improve performance for certain workloads but may also generate
``SIGSEGV/SIGBUS`` exceptions for some applications that specifically use
invalid pointers (though this is not expected for most real-world applications).

Stack size
^^^^^^^^^^

::

    sys.stack.size = "[SIZE]"
    (default: "256K")

This specifies the stack size of each thread in each Gramine process. The
default value is determined by the library OS. Units like ``K`` |~| (KiB),
``M`` |~| (MiB), and ``G`` |~| (GiB) can be appended to the values for
convenience. For example, ``sys.stack.size = "1M"`` indicates a 1 |~| MiB stack
size.

Program break (brk) size
^^^^^^^^^^^^^^^^^^^^^^^^

::

    sys.brk.max_size = "[SIZE]"
    (default: "256K")

This specifies the maximal program break (brk) size in each Gramine process.
The default value of the program break size is determined by the library OS.
Units like ``K`` (KiB), ``M`` (MiB), and ``G`` (GiB) can be appended to the
values for convenience. For example, ``sys.brk.max_size = "1M"`` indicates
a 1 |~| MiB brk size.

Allowing eventfd
^^^^^^^^^^^^^^^^

::

    sys.insecure__allow_eventfd = [true|false]
    (Default: false)

This specifies whether to allow system calls `eventfd()` and `eventfd2()`. Since
eventfd emulation currently relies on the host, these system calls are
disallowed by default due to security concerns.

External SIGTERM injection
^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sys.enable_sigterm_injection = [true|false]
    (Default: false)

This specifies whether to allow for a one-time injection of `SIGTERM` signal
into Gramine. Could be useful to handle graceful shutdown.
Be careful! In SGX environment, the untrusted host could inject that signal in
an arbitrary moment. Examine what your application's `SIGTERM` handler does and
whether it poses any security threat.

Disallowing subprocesses (fork)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sys.disallow_subprocesses = [true|false]
    (Default: false)

This specifies whether to block applications from creating child processes (e.g.
via ``fork()`` or ``clone()`` system calls). The intuition is that many
applications have fallbacks when they fail to spawn a child process (e.g.
Python). Could be useful in SGX environments: child processes consume
:term:`EPC` memory which is a limited resource.

.. note ::
   This option is *not* a security feature - Gramine by-design is only a one-way
   sandbox, which doesn't protect the host from the enclave. Don't use this
   option if you want to somehow mitigate running untrusted enclaves. Instead,
   to achieve this, you need to run the whole Gramine inside a proper security
   sandbox.

Root FS mount point
^^^^^^^^^^^^^^^^^^^

::

    fs.root.type = "[chroot|...]"
    fs.root.uri  = "[URI]"

This syntax specifies the root filesystem to be mounted inside the library OS.
Both parameters are optional. If not specified, then Gramine mounts the current
working directory as the root.

FS mount points
^^^^^^^^^^^^^^^

::

    fs.mounts = [
      { type = "[chroot|...]", path = "[PATH]", uri = "[URI]" },
      { type = "[chroot|...]", path = "[PATH]", uri = "[URI]" },
    ]

Or, as separate sections:

::

    [[fs.mounts]]
    type = "[chroot|...]"
    path = "[PATH]"
    uri  = "[URI]"

    [[fs.mounts]]
    type = "[chroot|...]"
    path = "[PATH]"
    uri  = "[URI]"

This syntax specifies how filesystems are mounted inside the library OS. For
dynamically linked binaries, usually at least one `chroot` mount point is
required in the manifest (the mount point of linked libraries). The filesystems
will be mounted in the order in which they appear in the manifest.

.. note::
   Keep in mind that TOML does not allow trailing commas in inline tables:
   ``{ path = "...", uri = "...", }`` is a syntax error.

The ``type`` parameter specifies the mount point type. If omitted, it defaults
to ``"chroot"``. The ``path`` parameter must be an absolute path (i.e., must
begin with ``/``).

Gramine currently supports the following types of mount points:

* ``chroot`` (default): Host-backed files. All host files and sub-directories
  found under ``[URI]`` are forwarded to the Gramine instance and placed under
  ``[PATH]``. For example, with a host-level path specified as ``uri =
  "file:/one/path/"`` and forwarded to Gramine via ``path = "/another/path"``, a
  host-level file ``/one/path/file`` is visible to graminized application as
  ``/another/path/file``. This concept is similar to FreeBSD's chroot and to
  Docker's named volumes. Files under ``chroot`` mount points support mmap and
  fork/clone.

* ``encrypted``: Host-backed encrypted files. See :ref:`encrypted-files` for
  more information.

* ``untrusted_shm``: Untrusted shared memory files. See
  :ref:`untrusted-shared-memory` for more information.

* ``tmpfs``: Temporary in-memory-only files. These files are *not* backed by
  host-level files. The tmpfs files are created under ``[PATH]`` (this path is
  empty on Gramine instance startup) and are destroyed when a Gramine instance
  terminates. The ``[URI]`` parameter is always ignored and can be omitted.

  ``tmpfs`` is especially useful in trusted environments (like Intel SGX) for
  securely storing temporary files. This concept is similar to Linux's tmpfs.
  Files under ``tmpfs`` mount points currently do *not* support mmap and each
  process has its own, non-shared tmpfs (i.e., processes don't see each other's
  files).

Start (current working) directory
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    fs.start_dir = "[URI]"

This syntax specifies the start (current working) directory. If not specified,
then Gramine sets the root directory as the start directory (see ``fs.root``).

Allowed IOCTLs
^^^^^^^^^^^^^^

::

    sys.ioctl_structs.[identifier] = [memory-layout-format]

    sys.allowed_ioctls = [
      { request_code = [NUM], struct = "[identifier-of-ioctl-struct]" },
    ]

By default, Gramine disables all device-backed and socket IOCTLs. This syntax
allows to explicitly allow a set of IOCTLs on devices (devices must be
explicitly mounted via ``fs.mounts`` manifest syntax) and sockets (e.g. for
``SIOCGIFCONF`` and ``SIOCGIFHWADDR``). Only IOCTLs with the ``request_code``
argument found among the manifest-listed IOCTLs are allowed to pass-through to
the host. Each IOCTL entry may also contain a reference to an IOCTL struct in
the ``struct`` field, in case the third IOCTL argument is intended to be
translated by Gramine.

Available IOCTL structs are described via ``sys.ioctl_structs``. Each IOCTL
struct describes the memory layout of the third argument to the ``ioctl`` system
call (typically a pointer to a complex nested object passed to the device).
Description of the memory layout is required for a deep copy of the IOCTL
struct. Here we use the term *memory region* to denote a separate contiguous
region of memory and the term *sub-region of a memory region* to denote a part
of the memory region that has properties different from other sub-regions in the
same memory region (e.g., should it be copied in or out of Gramine memory, is it
a pointer to another memory region, etc.). For example, a C struct can be
considered one memory region, and fields of this C struct can be considered
sub-regions of this memory region.

We also use the terms *Gramine memory* and *host memory*. This distinction is
currently relevant only for SGX environments: Gramine memory means
in-SGX-enclave memory and host memory means outside-of-SGX-enclave untrusted
memory.

Memory layout of the IOCTL struct is described using the TOML syntax of inline
arrays (for each new separate memory region) and inline tables (for each
sub-region in one memory region). Each sub-region is described via the following
keys:

- ``name`` is an optional name for this sub-region; mainly used to find
  length-specifying sub-regions and nested memory regions.
- ``alignment`` is an optional alignment of the memory region; may be specified
  only in the first sub-region of a memory region (all other sub-regions are
  contiguous with the first sub-region, so specifying their alignment doesn't
  make sense). The default value is ``1``.
- ``size`` is the size of this sub-region. The ``size`` field may be a string
  with the name of another sub-region that contains the size value or an integer
  with the constant size measured in ``unit`` units (default unit is 1 byte;
  also see below). For example, ``size = "strlen"`` denotes a size field that
  will be calculated dynamically during IOCTL execution based on the sub-region
  named ``strlen``, whereas ``size = 16`` denotes a sub-region of size 16B. Note
  that ``ptr`` sub-regions must *not* specify the ``size`` field.
- ``unit`` is an optional unit of measurement for ``size``. It is 1 byte by
  default. Unit of measurement must be a constant integer. For example,
  ``size = "strlen"`` and ``unit = 2`` denote a wide-char string (where each
  character is 2B long) of a dynamically specified length.
- ``adjustment`` is an optional integer adjustment for ``size`` (always
  specified in bytes). It is 0 bytes by default. This field must be a constant
  (possibly negative) integer. For example, ``size = 6``, ``unit = 2`` and
  ``adjustment = -8`` results in a total size of 4B.
- ``direction = "none" | "out" | "in" | "inout"`` is an optional direction of
  copy for this sub-region (from the app point of view). For example,
  ``direction = "out"`` denotes a sub-region to be copied out of Gramine memory
  to host memory, i.e., this sub-region is an input to the host device. The
  default value is ``none`` which is useful for e.g. padding of structs. This
  field must be ommitted if the ``ptr`` field is specified for this sub-region
  (pointer sub-regions contain the pointer value which will be unconditionally
  rewired to point to host memory).
- ``ptr = inlined-memory-region`` or ``ptr = "another-ioctl-struct"``
  specifies a pointer to another, nested memory region. This field is required
  when describing complex IOCTL structs. Such pointer memory region always has
  the implicit size of 8B, and the pointer value is always rewired by Gramine to
  the memory region in host memory (containing a corresponding nested memory
  region). If ``ptr`` is specified together with ``array_len``, it describes an
  array of pointers to these memory regions. (In other words, ``ptr`` is an
  array of pointers to memory regions with ``array_len = 1`` by default.) This
  may be recursive with the ``NULL`` value being a guard, which allows
  describing linked lists.
- ``array_len`` is an optional number of items in the ``ptr`` array. This field
  cannot be specified with non-``ptr`` sub-regions. The default value is ``1``.
- ``onlyif = "simple boolean expression"`` allows to condition the sub-region
  based on a boolean expression. The sub-region is taken into account only if
  the expression evaluates to true. The only currently supported formats of
  expressions are ``token1 == token2`` and ``token1 != token2``, where
  ``token1`` and ``token2`` may be constant non-negative integers or sub-region
  names (referenced sub-regions must contain a native-endian integer value of
  size 1..8B).

Consider this simple C snippet:

.. code-block:: c

   struct ioctl_read {
       size_t buf_size;                /* copied from Gramine to device */
       char* buf;                      /* copied from device to Gramine */
   } __attribute__((aligned(0x1000))); /* alignment just for illustration */

This translates into the following manifest syntax::

    sys.ioctl_structs.ioctl_read = [
        {
            name      = "buf_size",
            size      = 8,
            direction = "out",
            alignment = 0x1000
        },
        {
            ptr = [
                {
                    size      = "buf_size",
                    direction = "in"
                }
            ]
        }
    ]

The above example specifies a root struct (first memory region) that consists of
two sub-regions: the first one contains an 8-byte size value, the second one is
an 8-byte pointer value. This pointer points to another memory region in Gramine
memory that contains a single sub-region of size ``buf_size``. This nested
sub-region is copied from the device into the Gramine memory.

IOCTLs that use the above struct in a third argument are defined like this::

    sys.allowed_ioctls = [
      { request_code = 0x12345678, struct = "ioctl_read" },
      { request_code = 0x87654321, struct = "ioctl_read" },
    ]

If the IOCTL's third argument should be passed directly as-is (or unused at
all), then the ``struct`` key must be an empty string or not exist at all::

    sys.allowed_ioctls = [
      { request_code = 0x43218765, struct = "" },
      { request_code = 0x87654321 },
    ]

.. note ::
   IOCTLs for device communication are pass-through and thus potentially
   insecure by themselves in e.g. SGX environments:

   - IOCTL arguments are passed as-is from the app to the untrusted host,
     which may lead to leaks of enclave data.
   - Untrusted host can change IOCTL arguments as it wishes when passing
     them from Gramine to the device and back.

   It is the responsibility of the app developer to correctly use IOCTLs, with
   security implications in mind. In most cases, IOCTL arguments should be
   encrypted or integrity-protected with a key pre-shared between Gramine and
   the device.

Experimental flock (BSD-style locks) support
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sys.experimental__enable_flock = [true|false]
    (Default: false)

This syntax enables the ``flock`` system call in Gramine.

.. warning::
   This syscall is still under development and may contain security
   vulnerabilities. This is temporary; the syscall will be enabled by default in
   the future after thorough validation and this syntax will be removed then.

.. _sgx-syntax:

SGX syntax
----------

If Gramine is *not* running with SGX, the SGX-specific syntax is ignored. All
keys in the SGX-specific syntax are optional.

Debug/production enclave
^^^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.debug = [true|false]
    (Default: false)

This syntax specifies whether the enclave can be debugged. Set it to ``true``
for a |~| debug enclave and to ``false`` for a |~| production enclave.

EDMM
^^^^

::

    sgx.edmm_enable = [true|false]
    (Default: false)

This setting enables the :term:`EDMM` feature (after-enclave-creation memory
management). If set to ``true``, Gramine will refuse to start on CPUs which do
not support :term:`EDMM` feature.

When this feature is enabled, Gramine does not add heap pages (uninitialized
memory) to the enclave at creation time. Instead, memory is added to the enclave
on demand. This can greatly reduce startup time for bigger enclaves, reduce
the :term:`EPC` usage (as only actually allocated memory is used) and allow for
changing memory permissions (without this Gramine allocates all dynamic memory
as RWX). Unfortunately it can negatively impact performance, as adding a page
to the enclave at runtime is a more expensive operation than adding the page
before enclave creation (because it involves more enclave exits and syscalls).

When this feature is enabled, it is not necessary to specify
``sgx.enclave_size`` (Gramine will automatically set it to 1TB which should be
enough for any application). However if ``sgx.enclave_size`` is specified, this
explicit value will take precedence.

.. note::
   Support for EDMM first appeared in Linux 6.0.

Enclave size
^^^^^^^^^^^^

::

    sgx.enclave_size = "[SIZE]"
    (default: "256M" without EDMM, "1024G" with EDMM)

This syntax specifies the size of the enclave set during enclave creation time
if :term:`EDMM` is not enabled (``sgx.edmm_enable = false``) or the maximal
size that the enclave can grow to if :term:`EDMM` is enabled
(``sgx.edmm_enable = true``).

The PAL and library OS code/data count towards this size value, as well as the
application memory itself: application's code, stack, heap, loaded application
libraries, etc. The application cannot allocate memory that exceeds this limit.

Be careful when setting the enclave size to large values: when creating enclaves
which do not have the :term:`EDMM` feature enabled, Gramine not only reserves
``sgx.enclave_size`` bytes of virtual address space but also *commits* them to
the backing store (EPC, RAM and/or swap file). For example, if
``sgx.enclave_size = "4G"``, then 4GB of EPC/RAM will be immediately allocated
to back the enclave memory (recall that :term:`EPC` is the SGX-protected part of
RAM). Thus, if your system has 4GB of backing store or less, then the host Linux
kernel will fail to start the SGX enclave and will typically print the
``Killed`` message. If you encounter this situation, you can try the following:

- If possible, decrease ``sgx.enclave_size`` to a value less than the amount of
  RAM. For example, if you have 4GB of RAM, set ``sgx.enclave_size = "2G"``.
- Switch to a system that has more RAM. For example, if you must use
  ``sgx.enclave_size = "4G"``, move to a system with at least 5GB of RAM.
- If the above options are ruled out, then increase the swap file size (recall
  that the swap file is a space on hard disk used as a virtual "extension" to
  real RAM). For example, if you have 4GB of RAM and you must use
  ``sgx.enclave_size = "4G"``, then create the swap file of size 1GB. Note that
  as soon as the SGX application starts using the swap file, its performance
  degrades significantly!

Also, be careful with multi-process SGX applications: each new child process
runs in its own SGX enclave and thus requires an additional ``sgx.enclave_size``
amount of RAM. For example, if you run ``bash -c ls`` and your manifest contains
``sgx.enclave_size = "4G"``, then two SGX enclaves (bash and ls processes) will
consume 8GB of RAM in total. If there is less than 8GB of RAM (+ swap file) on
your system, such ``bash -c ls`` SGX workload will fail. Note this does not
apply to the enclaves with :term:`EDMM` enabled, where memory is not reserved
upfront and is allocated on demand.

Number of threads
^^^^^^^^^^^^^^^^^

::

    sgx.max_threads = [NUM]
    (Default: 4)

If :term:`EDMM` is not enabled (``sgx.edmm_enable = false``), then this syntax
specifies the maximum number of threads that can be created inside the enclave
(recall that SGX |~| v1 requires a |~| predetermined maximum number of thread
slots). The application cannot have more threads than this limit *at a time*
(however, it is possible to create new threads after old threads are destroyed).

If :term:`EDMM` is enabled (``sgx.edmm_enable = true``), then this syntax
specifies the number of pre-allocated thread slots (must be at least ``1``).
However, the maximum number of threads can exceed this limit during enclave
execution, by dynamically allocating new thread slots.

Note that Gramine uses several helper threads internally:

- The IPC thread to facilitate inter-process communication. This thread is
  always spawned at Gramine startup. Its activity depends on the communication
  patterns among Gramine processes; if there is only one Gramine process, the
  IPC thread always sleeps.
- The Async thread to implement timers and other asynchronous
  events/notifications. This thread is spawned on demand. It terminates itself
  if there are no pending events/notifications.
- The TLS-handshake thread on pipes creation. This thread is spawned on demand,
  each time a new pipe is created. It terminates itself immediately after the
  TLS handshake is performed.

Given these internal threads, ``sgx.max_threads`` should be set to at least
``4`` even for single-threaded applications (to accommodate for the main thread,
the IPC thread, the Async thread and one TLS-handshake thread).

.. note::
   This option will be renamed after non-:term:`EDMM` platform support is
   dropped.

Number of RPC threads (Exitless feature)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.insecure__rpc_thread_num = [NUM]
    (Default: 0)

This syntax specifies the number of RPC threads that are created outside of
the enclave. RPC threads are helper threads that run in untrusted mode
alongside enclave threads. RPC threads issue system calls on behalf of enclave
threads. This allows "exitless" design when application threads never leave
the enclave (except for a few syscalls where there is no benefit, e.g.,
``nanosleep()``).

If the user specifies ``0`` or omits this directive, then no RPC threads are
created, and all system calls perform an enclave exit ("normal" execution).

Note that the number of created RPC threads should match the maximum number of
simultaneous enclave threads. If there are more RPC threads, then CPU time is
wasted. If there are less RPC threads, some enclave threads may starve,
especially if there are many blocking system calls by other enclave threads.

The Exitless feature *may be detrimental for performance*. It trades slow
OCALLs/ECALLs for fast shared-memory communication at the cost of occupying
more CPU cores and burning more CPU cycles. For example, a single-threaded
Redis instance on Linux becomes 5-threaded on Gramine with Exitless. Thus,
Exitless may negatively impact throughput but may improve latency.

This feature is currently marked as insecure, because it reads and writes to
untrusted memory in potentially insecure manner - susceptible to
CVE-2022-21233 (INTEL-SA-00657) and CVE-2022-21166 (INTEL-SA-00615)
respectively.

SGX EXINFO
^^^^^^^^^^

::

    sgx.use_exinfo = [true|false]
    (Default: false)

If ``sgx.use_exinfo`` is set, user application can retrieve faulting address in
signal handler in case of a page fault. Otherwise (set to ``false``), the
faulting address will always be provided as ``0``. The default is ``false``
because some frameworks/runtimes could otherwise print the callstack and
variables/registers on exceptions, potentially leaking data.

Optional CPU features (AVX, AVX512, AMX, MPX, PKRU)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.cpu_features.avx    = "[unspecified|disabled|required]"
    sgx.cpu_features.avx512 = "[unspecified|disabled|required]"
    sgx.cpu_features.amx    = "[unspecified|disabled|required]"
    (Default: "unspecified")

    sgx.cpu_features.mpx    = "[disabled|required]"
    sgx.cpu_features.pkru   = "[disabled|required]"
    (Default: "disabled")

For the SGX threat model, Gramine divides CPU features in two subsets:
not-security-hardening features (currently AVX, AVX512 and AMX) and
security-hardening features (MPX and PKRU).

The ``"unspecified"`` syntax applies only to not-security-hardening features. It
means that the enclave initialization will succeed regardless of whether the CPU
feature is available on the platform or not. The CPU features will be enabled in
the enclave if they are available on the platform. Security-hardening features
cannot be marked as ``"unspecified"`` because this would lead to different
security properties of the application on different platforms.

The ``"disabled"`` syntax disables the CPU feature inside the enclave even if
this CPU feature is available on the platform. This may improve enclave
performance because this CPU feature will *not* be saved and restored during
enclave entry/exit. This syntax is provided to improve performance of
applications that are known to *not* rely on certain CPU features. Be aware that
if the application relies on some disabled CPU features, the application will
fail with SIGILL ("illegal instruction"). For example, if the application is
built with AVX support, and AVX is disabled in the manifest, the application
will crash.

The ``"required"`` syntax ensures that the CPU feature is available and enabled
for the enclave. If such option is set in the manifest but the CPU feature is
unavailable on the platform, enclave initialization will fail.

When in doubt, it is recommended to keep the default values for these features.
In this case, Gramine auto-detects the corresponding not-security-hardening CPU
features on the platform and enables them if available, and disables
security-hardening CPU features. This allows the SGX enclave to be executed on
the widest range of platforms.

At the technical level, the mapping from CPU features to SGX fields is as
follows:

- ``"unspecified"``: ``SIGSTRUCT.ATTRIBUTEMASK[feature] = 0``. The untrusted
  loader of Gramine sets ``SECS.ATTRIBUTES[feature] = 0`` if it can't detect the
  feature on the platform, and ``SECS.ATTRIBUTES[feature] = 1`` otherwise.
- ``"required"``: ``SIGSTRUCT.ATTRIBUTEMASK[feature] = 1`` and
  ``SIGSTRUCT.ATTRIBUTES[feature] = 1``.
- ``"disabled"``: ``SIGSTRUCT.ATTRIBUTEMASK[feature] = 1`` and
  ``SIGSTRUCT.ATTRIBUTES[feature] = 0``.

ISV Product ID and SVN
^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.isvprodid = [NUM]
    sgx.isvsvn    = [NUM]
    (Default: 0)

This syntax specifies the ISV Product ID and SVN to be added to the enclave
signature.

Attribute masks for SGX sealing key derivation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.seal_key.flags_mask = "[8-byte hex value]"  (default: "0xffffffffffffffff")
    sgx.seal_key.xfrm_mask  = "[8-byte hex value]"  (default: "0xfffffffffff9ff1b")
    sgx.seal_key.misc_mask  = "[4-byte hex value]"  (default: "0xffffffff")

This syntax specifies masks used to generate the SGX sealing key. These masks
correspond to the following SGX ``KEYREQUEST`` struct fields:

- ``flags_mask``: ``KEYREQUEST.ATTRIBUTESMASK.FLAGS``
- ``xfrm_mask``: ``KEYREQUEST.ATTRIBUTESMASK.XFRM``
- ``misc_mask``: ``KEYREQUEST.MISCMASK``

Most users do *not* need to set these masks. Only advanced users with knowledge
of SGX sealing should use these masks. In particular, these masks allow to
specify a subset of enclave/machine attributes to be used in sealing key
derivation. Moreover, these masks themselves are used in sealing key derivation.

.. _allowed_files:

Allowed files
^^^^^^^^^^^^^

::

    sgx.allowed_files = [
      "[URI]",
      "[URI]",
    ]

This syntax specifies the files/directories (with the ``file:`` prefix) and
devices (with the ``dev:`` prefix) that are allowed to be created or opened in
the enclave unconditionally. In other words, allowed files, directories and
devices can be opened for reading/writing and can be created if they do not
exist already. Allowed files are not cryptographically hashed and are thus not
protected.

.. warning::
   It is insecure to allow files containing code or critical information;
   developers must not allow files blindly! Instead, use trusted or encrypted
   files.

   Similarly, communication with allowed devices is pass-through and thus
   potentially insecure by itself. It is the responsibility of the app developer
   to correctly communicate with devices, with security implications in mind.

Trusted files
^^^^^^^^^^^^^

::

    # entries can be strings
    sgx.trusted_files = [
      "[URI]",
      "[URI]",
    ]

    # entries can also be tables
    [[sgx.trusted_files]]
    uri = "[URI]"
    sha256 = "[HASH]"

This syntax specifies the files to be cryptographically hashed at build time; at
runtime, these files may only be accessed by the app if the files' hashes match
what is stored in the manifest. This implies that trusted files can be only
opened for reading (not for writing) and cannot be created if they do not exist
already. The signer tool will automatically generate hashes of these files and
add them to the SGX-specific manifest (``.manifest.sgx``). The manifest writer
may also specify the hash for a file using the TOML-table syntax, in the field
``sha256``; in this case, hashing of the file will be skipped by the signer tool
and the value in ``sha256`` field will be used instead.

Marking files as trusted is especially useful for shared libraries: a |~|
trusted library cannot be silently replaced by a malicious host because the hash
verification will fail.

.. _encrypted-files:

Encrypted files
^^^^^^^^^^^^^^^

::

    fs.mounts = [
      { type = "encrypted", path = "[PATH]", uri = "[URI]", key_name = "[KEY_NAME]" },
    ]

    fs.insecure__keys.[KEY_NAME] = "[32-character hex value]"

This syntax allows mounting files that are encrypted on disk and transparently
decrypted when accessed by Gramine or by application running inside Gramine.
Encrypted files guarantee data confidentiality and integrity (tamper
resistance), as well as file swap protection (an encrypted file can only be
accessed when in a specific host path).

Encrypted files were previously known as *protected files*, and some Gramine
tools might still use the old name.

URI can be a file or a directory. If a directory is mounted, all existing
files/directories within it are recursively treated as encrypted (and are
expected to be encrypted in the PF format). New files created in an encrypted
mount are also automatically treated as encrypted.

.. warning::
   The current implementation assumes that ``type = "encrypted"`` mounts do not
   overlap on host, i.e. there are no host files reachable through more than one
   ``type = "encrypted"`` mount. Otherwise, changes made to such files might not
   be correctly persisted by Gramine.

Note that path size of an encrypted file is limited to 512 bytes and filename
size is limited to 260 bytes.

The ``key_name`` mount parameter specifies the name of the encryption key. If
omitted, it will default to ``"default"``. This feature can be used to mount
different files or directories with different encryption keys.

``fs.insecure__keys.[KEY_NAME]`` can be used to specify the encryption keys
directly in manifest. This option must be used only for debugging purposes.

.. warning::
   ``sgx.insecure__keys.[KEY_NAME]`` hard-codes the key in the manifest. This
   option is thus insecure and must not be used in production environments!
   Typically, you want to provision the encryption keys using SGX
   local/remote attestation, thus you should not specify any
   ``sgx.insecure__keys.[KEY_NAME]`` manifest options at all. Instead, use the
   Secret Provisioning interface (see :doc:`attestation`).

Key names beginning with underscore (``_``) denote special keys provided by
Gramine:

* ``"_sgx_mrenclave"`` (SGX only) is the SGX sealing key based on the MRENCLAVE
  identity of the enclave. This is useful to allow only the same enclave (on the
  same platform) to unseal files.

* ``"_sgx_mrsigner"`` (SGX only) is the SGX sealing key based on the MRSIGNER
  identity of the enclave. This is useful to allow all enclaves signed with the
  same key (and on the same platform) to unseal files.

.. warning::
   The same key must not be used for the encrypted-files mount and for the
   application's own crypto operations. Such "double" use of the same key may
   lead to compromise of the key. For example, specifying an FS mount via
   ``{type = "encrypted", ..., key_name = "_sgx_mrenclave"}`` in the manifest
   and using the same key obtained via ``/dev/attestation/keys/_sgx_mrenclave``
   in the application is insecure. If you need to derive encryption keys from
   such a "doubly-used" key, you must apply a KDF.

.. _untrusted-shared-memory:

Untrusted shared memory
^^^^^^^^^^^^^^^^^^^^^^^

::

    fs.mounts = [
      { type = "untrusted_shm", path = "[PATH]", uri = "[URI]" },
    ]

This syntax allows mounting shared memory objects that are accessible by both
the application running inside Gramine and by other host software/hardware (host
OS, other host processes, devices connected to the host). In Gramine, untrusted
shared memory applies to files which must be mapped into application address
space with the ``MAP_SHARED`` flag.

URI can be a file or a directory (with a ``dev:`` prefix). If a directory is
mounted, all files under this directory are treated as shared memory objects
(but sub-directories are inaccessible for security reasons). New files created
in a shared memory mount are also automatically treated as shared memory
objects. Creating sub-directories in a shared memory mount is not allowed, for
security reasons. Files in a shared memory mount (or the mounted directory
itself) need to be explicitly listed as ``allowed_files`` to be accessed. See
:ref:`allowed_files` for more information.

Typically, you should mount the directory ``/dev/shm/`` (it is used for sharing
data between processes and devices) and allow specific files in it. When this
directory is mounted, the Gramine application may create the files -- called
"shared memory objects" in POSIX -- under this directory (for example, this is
how ``shm_open()`` Glibc function works). It is not recommended to allow a
directory unless the application creates shared memory objects with
unpredictable names. Allowing a directory creates a risk of exposing unexpected
data to the host.

.. note ::
   Adding shared memory mounts is insecure by itself in SGX environments:

       - All data put in shared memory reside outside of the SGX enclave.
       - Typically applications do not encrypt the data put in shared memory,
         which may lead to leaks of enclave data.
       - Untrusted host can modify data in shared memory as it wishes, so
         applications could see or operate on maliciously modified data.

   It is the responsibility of the app developer to correctly use shared memory,
   with security implications in mind. In most cases, data in shared memory
   should be preliminarily encrypted or integrity-protected by the user app
   with a key pre-shared between all participating processes (and possibly
   devices that use this shared memory).

File check policy
^^^^^^^^^^^^^^^^^

::

    sgx.file_check_policy = "[strict|allow_all_but_log]"
    (Default: "strict")

This syntax specifies the file check policy, determining the behavior of
authentication when opening files or devices. By default, only files explicitly
listed as ``trusted_files`` and files or devices explicitly listed as
``allowed_files`` are allowed for access.

If the file check policy is ``allow_all_but_log``, all files and devices other
than trusted and allowed are allowed for access, and Gramine emits a warning
message for every such file/device. Effectively, this policy operates on all
unknown files and devices as if they were listed as ``allowed_files``. (However,
this policy still does not allow writing/creating files specified as trusted.)
This policy is a convenient way to determine the set of files that the ported
application uses.

Attestation and quotes
^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.remote_attestation = "[none|epid|dcap]"
    (Default: "none")

    sgx.ra_client_linkable = [true|false]
    sgx.ra_client_spid     = "[HEX]"
    (Only for EPID based attestation)

This syntax specifies the parameters for remote attestation. By default, it is
not enabled.

For :term:`EPID` based attestation, ``remote_attestation`` must be set to
``epid``.  In addition, ``ra_client_linkable`` and ``ra_client_spid`` must be
filled with your registered Intel SGX EPID Attestation Service credentials
(linkable/unlinkable mode and :term:`SPID` of the client respectively).

For :term:`DCAP` based attestation, ``remote_attestation`` must be set to
``dcap``. ``ra_client_spid`` and ``ra_client_linkable`` are ignored.

Pre-heating enclave
^^^^^^^^^^^^^^^^^^^

::

    sgx.preheat_enclave = [true|false]
    (Default: false)

When enabled, this option instructs Gramine to pre-fault all heap pages during
initialization. This has a negative impact on the total run time, but shifts the
:term:`EPC` page faults cost to the initialization phase, which can be useful in
a scenario where a server starts and receives connections / work packages only
after some time. It also makes the later run time and latency much more
predictable.

Please note that using this option makes sense only when the :term:`EPC` is
large enough to hold the whole heap area.

This option is invalid (i.e. must be ``false``) if specified together with
``sgx.edmm_enable``, as there are no heap pages to pre-fault.

Enabling per-thread and process-wide SGX stats
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.enable_stats = [true|false]
    (Default: false)

This syntax specifies whether to enable SGX enclave-specific statistics:

#. ``TCS.FLAGS.DBGOPTIN`` flag. This flag is set in all enclave threads and
   enables certain debug and profiling features with enclaves, including
   breakpoints, performance counters, Intel PT, etc.

#. Printing the stats on SGX-specific events. Currently supported stats are:
   number of EENTERs (corresponds to ECALLs plus returns from OCALLs), number
   of EEXITs (corresponds to OCALLs plus returns from ECALLs) and number of
   AEXs (corresponds to interrupts/exceptions/signals during enclave
   execution). Prints per-thread and per-process stats.

#. Printing the SGX enclave loading time at startup. The enclave loading time
   includes creating the enclave, adding enclave pages, measuring them and
   initializing the enclave.

.. warning::
   This option is insecure and cannot be used with production enclaves
   (``sgx.debug = false``). If a production enclave is started with this option
   set, Gramine will fail initialization of the enclave.

SGX profiling
^^^^^^^^^^^^^

::

    sgx.profile.enable = ["none"|"main"|"all"]
    (Default: "none")

This syntax specifies whether to enable SGX profiling. Gramine must be compiled
with ``--buildtype=debug`` or ``--buildtype=debugoptimized`` for this option to
work (the latter is advised). In addition, the manifest must contain
``sgx.debug = true``.

If this option is set to ``main``, the main process will collect IP samples and
save them as ``sgx-perf.data``. If it is set to ``all``, all processes will
collect samples and save them to ``sgx-perf-<PID>.data``.

The saved files can be viewed with the ``perf`` tool, e.g. ``perf report -i
sgx-perf.data``.

See :ref:`sgx-profile` for more information.

.. warning::
   This option is insecure and cannot be used with production enclaves
   (``sgx.debug = false``). If a production enclave is started with this option
   set, Gramine will fail initialization of the enclave.

::

    sgx.profile.mode = ["aex"|"ocall_inner"|"ocall_outer"]
    (Default: "aex")

Specifies what events to record:

* ``aex``: Records enclave state during asynchronous enclave exit (AEX). Use
  this to check where the CPU time is spent in the enclave.

* ``ocall_inner``: Records enclave state during OCALL.

* ``ocall_outer``: Records the outer OCALL function, i.e., what OCALL handlers
  are going to be executed. Does not include stack information (cannot be used
  with ``sgx.profile.with_stack = true``).

See also :ref:`sgx-profile-ocall` for more detailed advice regarding the OCALL
modes.

::

    sgx.profile.with_stack = [true|false]
    (Default: false)

This syntax specifies whether to include stack information with the profiling
data. This will enable ``perf report`` to show call chains. However, it will
make the output file much bigger, and slow down the process.

::

    sgx.profile.frequency = [INTEGER]
    (Default: 50)

This syntax specifies approximate frequency at which profiling samples are taken
(in samples per second). Lower values will mean less accurate results, but also
lower overhead.

Note that the accuracy is limited by how often the process is interrupted by
Linux scheduler: the effective maximum is 250 samples per second.

.. note::
   This option applies only to ``aex`` mode. In the ``ocall_*`` modes, currently
   all samples are taken.

SGX profiling with Intel VTune Profiler
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.vtune_profile = [true|false]
    (Default: false)

This syntax specifies whether to enable SGX profiling with Intel VTune Profiler.
Gramine must be compiled with ``--buildtype=debug`` or
``--buildtype=debugoptimized`` for this option to work (the latter is advised).
In addition, the application manifest must also contain ``sgx.debug = true``.

.. note::
   The manifest options ``sgx.vtune_profile`` and ``sgx.profile.*`` can work
   independently.

See :ref:`vtune-sgx-profiling` for more information.

Deprecated options
------------------

Optional CPU features (deprecated syntax)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.require_avx    = [true|false]
    sgx.require_avx512 = [true|false]
    sgx.require_mpx    = [true|false]
    sgx.require_pkru   = [true|false]
    sgx.require_amx    = [true|false]

This syntax specified whether to require certain CPU features to be available on
the platform where the enclave executes. This syntax has been replaced with
``sgx.cpu_features.[avx|avx512|mpx|pkru|amx]``.

Previously, the default value for these features was ``false``. This was
ambiguous because e.g. ``sgx.require_avx = false`` meant that the AVX feature
was auto-detected on the platform, whereas ``sgx.require_mpx = false`` meant
that the MPX feature was always disabled inside the enclave.

.. note ::
   Previously, security-hardening features (MPX and PKRU) were underspecified.
   For example, ``sgx.require_mpx = false`` meant that the MPX feature was
   always disabled inside the enclave (regardless of whether the CPU supported
   it or not), and ``sgx.require_mpx = true`` meant that the MPX feature was
   always enabled inside the enclave (even if the CPU did not support it, which
   would result in enclave failures). This is in contrast to
   non-security-hardening features (AVX, AVX512, AMX) which could be
   "unspecified". The new manifest syntax fixes this ambiguity.

SGX EXINFO (deprecated syntax)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

::

    sgx.require_exinfo = [true|false]

This syntax specified whether a user application can retrieve faulting address
in signal handler in case of a page fault. This syntax was renamed to
``sgx.use_exinfo``. The default value was ``false``.
