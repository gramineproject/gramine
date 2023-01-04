*****************
Initramfs builder
*****************

Set of scripts to build and run the virtual machine. Uses host kernel for
simplicity. Whole host filesystem ("/") is mounted readonly at root with a
read-write overlay in tmpfs (volatile in memory). This is done for simplicity,
so that we don't have to build Gramine inside VM, provide all dependencies, etc.

In order to run Gramine SGX PAL inside QEMU, you need both QEMU and host kernel
to support SGX. The support was added in Linux v5.15 and QEMU v6.2.0. Ubuntu
22.04 comes with both in appropriate versions, so it's the easiest to just use
it.
