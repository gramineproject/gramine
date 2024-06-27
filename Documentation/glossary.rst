Glossary
========

.. keep this file sorted lexicographically

.. glossary::

   PAL
      Platform Adaptation Layer

      PAL is the layer of Gramine that implements a narrow Drawbridge-like ABI
      interface (with function names starting with the `Pal` prefix)

      .. seealso::

         https://www.microsoft.com/en-us/research/wp-content/uploads/2016/02/asplos2011-drawbridge.pdf

      Whenever Gramine requires a service from the host platform (memory
      allocation, thread management and synchronization, filesystem and network
      stacks, etc.), it calls the corresponding PAL functionality. The PAL ABI
      is host-platform agnostic and is backed by the host-platform specific PAL,
      for example, the Linux-SGX PAL.

   RA-TLS
   Interoperable RA-TLS
      A library to augment classic SSL/TLS sessions with
      :term:`Remote Attestation`. RA-TLS extends the SSL/TLS handshake protocol
      to force one endpoint into verifying the :term:`SGX Quote` embedded into
      the other endpoint's certificate chain. RA-TLS is designed to be a drop-in
      replacement for classic SSL/TLS libraries.

      Starting from v1.8, Gramine's RA-TLS library supports `Interoperable
      RA-TLS <https://github.com/CCC-Attestation/interoperable-ra-tls/>`__, a
      specification that modifies the original RA-TLS format for
      interoperability between different TEE frameworks. For example, Gramine
      applications can now establish secure connections with Occlum and
      OpenEnclave applications thanks to Interoperable RA-TLS. Previously, the
      RA-TLS library in Gramine was *not* interoperable with remote-attestation
      libraries from other projects, because RA-TLS used its own ad-hoc format
      of the X.509 certificate and embedded the SGX Quote in a non-standard way.

      .. seealso::

         :doc:`attestation`

   Secret Provisioning
      Secret provisioning is a mechanism to deliver secrets (such as encryption
      keys, passwords, etc.) from a remote trusted party inside a :term:`TEE`.
      It is typically built on top of a :term:`Secure Channel`.

      .. seealso::

         :doc:`attestation`

   Secure Channel
      Secure channels are communication channels for trusted transmission of
      arbitrary data between a :term:`TEE` and a remote trusted party or between
      two TEEs. They are typically built on top of the classic TLS/SSL channels.

      .. seealso::

         :doc:`attestation`

   SGX
      Software Guard Extensions is a set of instructions on Intel processors for
      creating Trusted Execution Environments (:term:`TEE`). See
      :doc:`/sgx-intro`.

   Thread Control Block

      .. todo:: TBD
