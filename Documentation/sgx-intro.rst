Introduction to SGX
===================

.. highlight:: sh

The Gramine project uses the :term:`Intel SGX <SGX>` (Software Guard Extensions)
technology to protect software running on untrusted hosts. SGX is a |~|
complicated topic, which may be hard to learn, because the documentation is
scattered through official/reference documentation, blogposts and academic
papers. This page is an attempt to curate a |~| dossier of available reading
material.

SGX is an umbrella name of *technology* that comprises several parts:

- CPU/platform *hardware features*: the instruction set, microarchitecture with
  the :term:`PRM` memory region and some new MSRs, some new logic in the MMU
  and so on;
- the SGX :term:`Remote Attestation` *infrastructure*, online services provided
  by Intel and/or third parties (see :term:`DCAP`);
- :term:`SDK` and assorted *software*.

SGX is still being developed. The current (March 2024) version of CPU features
is referred to as ":term:`SGX2`" or simply "SGX". The older instruction set
from the original SGX is informally referred to as ":term:`SGX1`".

Features which might be considered part of SGX2:

- :term:`EDMM` (Enclave Dynamic Memory Management)
- :term:`FLC` (Flexible Launch Control; not strictly part of SGX2, but was not
  part of original SGX hardware either)
- :term:`KSS` (Key Separation and Sharing; also not part of SGX2, but was not
  part of original SGX hardware either)

Around 2022 Intel discontinued SGX support in client CPU cores, and instead
introduced it to server cores. The new SGX hardware architecture didn't change
the user-facing ABI, but loosened security guarantees, matching AMD SEV-SNP
security model:

- Merkle tree for memory integrity checking was removed.
- Hardware RAM MitM attacks are not mitigated anymore: (because of Merkle tree
  removal)

  - On Icelake server CPUs there's no integrity protection at all.
  - On Sapphire Rapids server CPUs there's a 28-bit MAC per each cacheline.
    It's possible to bruteforce the MAC or do a replay attack with cacheline
    granularity (but that still requires a hardware MitM).

- EPC can now be almost arbitrarily big, significantly improving performance for
  large workloads.

As of now most of the broadly used server CPUs support :term:`SGX2`. Only older
client CPUs support SGX, so they should not be used in production (because of
missing security patches for side-channels).

Introductory reading
--------------------

.. note::

   Most of the older literature available (especially introduction-level)
   concerns the original :term:`SGX1` only.

- Quarkslab's two-part "Overview of Intel SGX":

  - `Part 1, SGX Internals (Quarkslab)
    <https://blog.quarkslab.com/overview-of-intel-sgx-part-1-sgx-internals.html>`__
  - `Part 2, SGX Externals (Quarkslab)
    <https://blog.quarkslab.com/overview-of-intel-sgx-part-2-sgx-externals.html>`__

- `MIT's deep dive in SGX architecture <https://eprint.iacr.org/2016/086>`__.

- Intel's whitepapers:

  - `Innovative Technology for CPU Based Attestation and Sealing
    <https://software.intel.com/en-us/articles/innovative-technology-for-cpu-based-attestation-and-sealing>`__
  - `Innovative Instructions and Software Model for Isolated Execution
    <https://software.intel.com/en-us/articles/innovative-instructions-and-software-model-for-isolated-execution>`__
  - `Using Innovative Instructions to Create Trustworthy Software Solutions [PDF]
    <https://software.intel.com/sites/default/files/article/413938/hasp-2013-innovative-instructions-for-trusted-solutions.pdf>`__
  - `Slides from ISCA 2015 <https://sgxisca.weebly.com/>`__
    (`actual slides [PDF] <https://software.intel.com/sites/default/files/332680-002.pdf>`__)

- `Hardware compatibility list (unofficial) <https://github.com/ayeks/SGX-hardware>`__

Official documentation
----------------------

- `Intel® 64 and IA-32 Architectures Software Developer's Manual Volume 3D:
  System Programming Guide, Part 4
  <https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3d-part-4-manual.pdf>`__
- `SDK for Linux <https://01.org/intel-software-guard-extensions/downloads>`__
  (download of both the binaries and the documentation)

Academic research
-----------------

- `Intel's collection of academic papers
  <https://software.intel.com/en-us/sgx/documentation/academic-research>`__,
  likely the most comprehensive list of references

Installation instructions
-------------------------

See :doc:`sgx-setup`.

Linux kernel drivers
^^^^^^^^^^^^^^^^^^^^

For historical reasons, there are three SGX drivers currently (March 2024):

- https://github.com/intel/linux-sgx-driver -- old one, does not support DCAP,
  deprecated

- https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/driver
  -- out-of-tree, supports both non-DCAP software infrastructure (with old EPID
  remote-attestation technique) and the new DCAP (with new ECDSA and
  more "normal" PKI infrastructure). Deprecated in favor of the upstreamed
  driver (see below).

- The upstreamed Linux driver -- SGX support was upstreamed to the Linux
  mainline starting from 5.11. It currently supports only DCAP attestation.

  Also, it doesn't require :term:`IAS` and kernel maintainers consider
  non-writable :term:`FLC` MSRs as non-functional SGX:
  https://lore.kernel.org/lkml/20191223094614.GB16710@zn.tnic/

SGX terminology
---------------

.. keep this sorted by full (not abbreviated) terms, leaving out generic terms
   like "Intel" and "SGX"

.. glossary::

   Architectural Enclaves
   AE

      Architectural Enclaves (AEs) are a |~| set of "system" enclaves concerned
      with starting and attesting other enclaves. Intel provides reference
      implementations of these enclaves, though other companies may write their
      own implementations.

      .. seealso::

         :term:`Provisioning Enclave`

         :term:`Launch Enclave`

         :term:`Quoting Enclave`

   Architectural Enclave Service Manager
   AESM

      The Architectural Enclave Service Manager is responsible for providing SGX
      applications with access to the :term:`Architectural Enclaves`. It consists
      of the Architectural Enclave Service Manager Daemon, which hosts the enclaves,
      and a component of the SGX SDK, which communicates with the daemon over a Unix
      socket with the fixed path :file:`/var/run/aesmd/aesm.sock`.

   Asynchronous Enclave Exit
   AEX

      An event caused by an exception occurring during in-enclave execution. CPU
      saves the current context into :term:`SSA`, leaves SGX mode and jumps
      to :term:`AEP`.

   Asynchronous Exit Pointer
   AEP

      An address outside the enclave where CPU will jump in case an exception
      happens during in-enclave execution.

   Attestation

      Attestation is a mechanism to prove the trustworthiness of the SGX enclave
      to a local or remote party. More specifically, SGX attestation proves that
      the enclave runs on a real hardware in an up-to-date TEE with the expected
      initial state. There are two types of the attestation:
      :term:`Local Attestation` (between enclaves on the same machines)
      and :term:`Remote Attestation` (between enclave and any party, possibly
      remote).

      .. seealso::

         :doc:`attestation`

         :term:`Local Attestation`

         :term:`Remote Attestation`

   Attestation result

      In the context of remote attestation, the :term:`verifier` issues an
      attestation result after evaluating the :term:`attestation evidence`
      issued by the :term:`TEE`. The resulting evidence is typically a signed
      token (e.g., a JSON Web Token) with a public key signature that the
      client can check locally. The specific contents of the result vary by
      attestation protocol, but typically include information about the
      :term:`attester` (TEE) such as the hash of the public key generated by the
      attester and its identity measurements.

      As a particular example, :term:`Microsoft Azure Attestation` and
      :term:`Intel Trust Authority` generate attestation results in the form of
      JSON Web Tokens (JWTs). As another example, :term:`Intel Attestation
      Service` generates the attestation result as a JSON report.

   Attester

      In the context of remote attestation, the attester produces believable
      information about itself (:term:`attestation evidence`) to enable a remote
      peer (:term:`relying party`) to decide whether to consider that attester a
      trustworthy peer. The evidence contains :term:`attestation
      claims<attestation claim>` that describe the attester's integrity and
      trustworthiness, as well as the signature that proves the claims.

      Different protocols specify different routes for the relying party to
      receive attestation evidence, see :term:`passport model` and
      :term:`background check model`.

      In Gramine, the Gramine SGX enclave serves the role of attester. The
      enclave generates the attestation evidence (SGX quote plus additional
      attestation claims) and sends it either directly to the verifier or to the
      relying party, which then will forward it to the verifier.

   Attestation claim

      In the context of remote attestation, the attestation claim is a
      machine-readable assertion about an :term:`attester`, which describes
      security-relevant properties, attributes or identifiers that can be
      included in :term:`attestation evidence`, :term:`attestation endorsement`,
      :term:`attestation result` or :term:`attestation policy`.

      Common examples of attestation claims might include the hash of an SGX
      enclave's address space contents at the start of execution, or the
      firmware version installed on the CPU at execution time.

      As a particular example, an Intel SGX quote (attestation evidence)
      contains an attestation claim ``MRENCLAVE = <SHA256 hash of initial
      enclave state>``. Similarly, an :term:`attestation policy` installed in
      e.g. :term:`Microsoft Azure Attestation` (verifier) may contain a claim
      ``MRENCLAVE = <expected SHA256 hash of initial enclave state>``. Finally,
      an attestation result from Microsoft Azure Attestation may contain a claim
      ``IS_MRENCLAVE_EXPECTED = true|false``.

   Background check model
   Background check attestation model

      :term:`Attestation` protocols can be grouped by which party the
      :term:`attester` relays :term:`attestation evidence` from the :term:`TEE`
      to; in all protocols, the attestation evidence eventually finds its way to
      the :term:`relying party`. In the background check model, the attester
      sends attestation evidence to the :term:`relying party`, which then
      forwards the attestation evidence to the verifier. In other words, the
      relying party performs the background check on the attester.

      In contrast, in the :term:`passport model`, the attester sends attestation
      evidence to the verifier.

      Gramine supports the background check model.

   Data Center Attestation Primitives
   DCAP

      A |~| software infrastructure provided by Intel as a reference
      implementation for the new ECDSA/:term:`PCS`-based remote attestation.
      Relies on the :term:`Flexible Launch Control` hardware feature.

      This allows for launching enclaves with Intel's remote infrastructure
      only involved in the initial setup. Naturally however, this requires
      deployment of own infrastructure, so is operationally more complicated.
      Therefore it is intended for server environments (where you control all
      the machines).

      .. seealso::

         Orientation Guide
            https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/DCAP_ECDSA_Orientation.pdf

         :term:`EPID`
            A |~| way to launch enclaves with Intel's infrastructure, intended
            for client machines.

   ECALL

      A |~| special function call made by non-enclave world into an enclave.

   Enclave

      An instance of SGX TEE, residing in a contiguous chunk of usermode address
      space (``ELRANGE``) of some process on the system. Application threads
      may enter and exit the enclave through dedicated CPU instructions. Code
      running inside an enclave has access to usermode memory of the process
      which contains it, but not the other way.

   Enclave Dynamic Memory Management
   EDMM

      A |~| hardware feature of :term:`SGX2`, allows for dynamic (in enclave
      runtime) addition and removal of enclave threads and memory, as well as
      changing memory permissions and type.

   Attestation endorsement

      In the context of remote attestation, an attestation endorsement is a
      statement that an :term:`endorser` vouches for the integrity of an
      :term:`attester`'s various capabilities. Endorsements might describe the
      ways in which the attester resists attacks, protects secrets, and measures
      its :term:`TEE`. One example of an endorsement is a manufacturer
      certificate that signs a public key whose corresponding private key is
      only known inside the device's hardware.

      Typically, the :term:`verifier` collects attestation endorsements from
      :term:`endorsers<endorser>` and stores them in a local database. Upon
      receiving an :term:`attestation evidence`, the verifier queries this
      database, combines it with the :term:`attestation policy` and emits an
      :term:`attestation result`.

   Endorser

      In the context of remote attestation, the endorser creates, provisions, or
      transfers an :term:`attestation endorsement` to the :term:`verifier`.

      As a particular example, :term:`Intel Provisioning Certification Service`
      is an endorser.

   Enclave Page Cache
   EPC

      A |~| part of :term:`PRM` used for caching enclave pages. :term:`EPC` is
      only an optimization and its size doesn't limit possible enclave sizes,
      though too-small :term:`EPC` may lead to frequent page swapping and
      significantly worsen performance.

   Enclave Page Cache Map
   EPCM

      A |~| part of :term:`PRM` which holds metadata about EPC pages.

   Enhanced Privacy Identification
   Enhanced Privacy Identifier
   EPID

      EPID is the attestation protocol originally shipped with SGX. Unlike
      :term:`DCAP`, a |~| remote verifier making use of the EPID protocol needs
      to contact the :term:`Intel Attestation Service` each time it wishes
      to attest an |~| enclave.

      Contrary to DCAP, EPID may be understood as "opinionated", with most
      moving parts fixed and tied to services provided by Intel. This is
      intended for client enclaves and deprecated for server environments.

      EPID attestation can operate in two modes: *fully-anonymous (unlinkable)
      quotes* and *pseudonymous (linkable) quotes*.  Unlike fully-anonymous
      quotes, pseudonymous quotes include an |~| identifier dependent on the
      identity of the CPU and the developer of the enclave being quoted, which
      allows determining whether two instances of your enclave are running on
      the same CPU or not.

      If your security model depends on enforcing that the identifiers are
      different (e.g. because you want to prevent sybil attacks), keep in mind
      that the enclave host can generate a new identity by performing an
      epoch reset. The previous identity will then become inaccessible, though.

      The attestation mode being used can be chosen by the application enclave,
      but it must match what was chosen when generating the :term:`SPID`.

      .. seealso::

         :term:`DCAP`
            A way to launch enclaves without relying on the Intel's
            infrastructure (after initial setup).

         :term:`SPID`
            An identifier one can obtain from Intel, required to make use of EPID
            attestation.

   Attestation evidence

      Set of :term:`attestation claims<attestation claim>` asserted by an
      attester about the :term:`Trusted Execution Environment` plus the
      attester's signature over these claims. The evidence must be transferred
      from the :term:`attester` to the :term:`verifier`. The attestation claims
      must be authenticatable, i.e. they must provide a way to the verifier to
      reason about authenticity of the TEE.

      As a particular example, the :term:`Interoperable RA-TLS` creates the
      SGX-enclave attestation evidence as a set of the following attestation
      claims: an SGX quote, a hash of the public key generated inside the SGX
      enclave and an optional nonce.

      Note that this definition is taken from the :term:`TCG DICE` standard and
      differs from the typical meaning in conversational English (where a claim
      is the higher-level statement and the evidence supports this claim). In
      the TCG DICE nomenclature, the distinction between evidence and claims is
      that evidence is a set of signed claims. We use the TCG DICE definitions
      for the sake of standard conformity.

   Flexible Launch Control
   FLC

      Hardware (CPU) feature that allows substituting :term:`Launch Enclave` for
      one not signed by Intel through a |~| change in SGX's EINIT logic to not
      require the EINITTOKEN from the Intel-based Launch Enclave. An |~| MSR,
      which can be locked at boot time, keeps the hash of the public key of
      the "launching" entity.

      With FLC, :term:`Launch Enclave` can be written by other companies (other
      than Intel) and must be signed with the key corresponding to the one
      locked in the MSR (a |~| reference Launch Enclave simply allows all
      enclaves to run). The MSR can also stay unlocked and then it can be
      modified at run-time by the VMM or the OS kernel.

      Support for FLC can be detected using ``CPUID`` instruction, as
      ``CPUID.07H:ECX.SGX_LC[bit 30] == 1`` (SDM vol. 2A calls this "SGX Launch
      Control").

      .. seealso::

         https://software.intel.com/en-us/blogs/2018/12/09/an-update-on-3rd-party-attestation
            Announcement

         :term:`DCAP`

   Key Separation and Sharing
   KSS
      A feature that lets developer define additional enclave identity
      attributes and configuration identifier. Extended enclave identity
      is defined by the developer on enclave build. Enclave configuration is
      defined on enclave launch and cannot be modified afterwards.

      In addition to the calculated enclave and signer measurements, developer
      is expected to define a product ID and :term:`SVN` for her enclaves.
      These identifiers are part of the :term:`SGX Report` and are expected to
      be used in :term:`Attestation`. They are also used by SGX key derivation
      to derive different keys per configuration.

      KSS adds two more attributes for enclave build and two new ones for
      enclave launch, which are part of the :term:`SGX Report`.
      Additionally, key policy attributes are extended to provide fine-grained
      control over key derivation.

      New build attributes:

      - Extended product ID
      - Family ID

      New enclave launch attributes:

      - Config ID
      - Config SVN

      This feature was not part of original SGX and therefore is not supported
      by all SGX-enabled hardware.

   Launch Enclave
   LE

      .. todo:: TBD

      .. seealso::

         :term:`Architectural Enclaves`

   Local Attestation

      In local attestation, the attesting SGX enclave collects
      :term:`attestation evidence` in the form of an :term:`SGX Report` using
      the EREPORT hardware instruction. This form of attestation is used to send
      the attestation evidence to a local party (on the same physical machine).

      .. seealso::

         :doc:`attestation`

   Intel Attestation Service
   IAS

      Internet service provided by Intel for "old" :term:`EPID`-based remote
      attestation. The SGX enclave (:term:`attester`) sends its SGX quote
      (:term:`attestation evidence`) to the :term:`relying party` who will
      forward this SGX quote to IAS (:term:`verifier`) to check the attester's
      trustworthiness.

      .. seealso::

         :term:`PCS`
            Provisioning Certification Service, another Internet service
            provided by Intel.

   Intel Trust Authority
   ITA

      Internet service provided by Intel for all types of Intel-based remote
      attestation. In case of Intel SGX, the SGX enclave (:term:`attester`)
      sends its SGX quote (:term:`attestation evidence`) to the :term:`relying
      party` who will forward this SGX quote to ITA (:term:`verifier`) to check
      the attester's trustworthiness. ITA returns the :term:`attestation result`
      in a JSON Web Token (JWT) format. Users can install their own
      :term:`attestation policies<attestation policy>` into ITA.

   Memory Encryption Engine
   MEE

      .. todo:: TBD

   Microsoft Azure Attestation
   MAA

      Internet service provided by Microsoft for remote attestation in the Azure
      cloud platform. In case of Intel SGX, the SGX enclave (:term:`attester`)
      sends its SGX quote (:term:`attestation evidence`) to the :term:`relying
      party` who will forward this SGX quote to MAA (:term:`verifier`) to check
      the attester's trustworthiness. MAA returns the :term:`attestation result`
      in a JSON Web Token (JWT) format. Users can install their own
      :term:`attestation policies<attestation policy>` into MAA.

   OCALL

      A |~| special function call made by an enclave to the non-enclave world.

   SGX Platform Software
   PSW

      Software infrastructure provided by Intel with all special
      :term:`Architectural Enclaves` (:term:`Provisioning Enclave`,
      :term:`Quoting Enclave`, :term:`Launch Enclave`). This mainly refers to
      the "old" EPID/IAS-based remote attestation.

   Processor Reserved Memory
   PRM

      A |~| mostly undocumented region of physical address space reserved by the
      BIOS for internal use by SGX hardware. Known to contain at
      least :term:`EPC` and :term:`EPCM`.

   Provisioning Enclave
   PE

      One of the Architectural Enclaves of the Intel SGX software
      infrastructure. It is part of the :term:`SGX Platform Software`. The
      Provisioning Enclave is used in :term:`EPID` based remote attestation.
      This enclave communicates with the Intel Provisioning Service
      (:term:`IPS`) to perform EPID provisioning. The result of this
      provisioning procedure is the private EPID key securely accessed by the
      Provisioning Enclave. This procedure happens only during the first
      deployment of the SGX machine (or, in rare cases, to provision a new EPID
      key after TCB upgrade). The main user of the Provisioning Enclave is the
      :term:`Quoting Enclave`.

      .. seealso::

         :term:`Architectural Enclaves`

   Provisioning Certification Enclave
   PCE

      One of the Architectural Enclaves of the Intel SGX software
      infrastructure. It is part of the :term:`SGX Platform Software` and
      :term:`DCAP`. The Provisioning Certification Enclave is used in
      :term:`DCAP` based remote attestation.  This enclave communicates with the
      Intel Provisioning Certification Service (:term:`PCS`) to perform DCAP
      provisioning. The result of this provisioning procedure is the DCAP/ECDSA
      attestation collateral (mainly the X.509 certificate chains rooted in a
      well-known Intel certificate and Certificate Revocation Lists). This
      procedure happens during the first deployment of the SGX machine and then
      periodically to refresh the cached attestation collateral. Typically, to
      reduce the dependency on PCS, a cloud service provider introduces an
      intermediate caching service (Provisioning Certification Caching Service,
      or PCCS) that stores all the attestation collateral obtained from Intel.
      The main user of the Provisioning Certification Enclave is the
      :term:`Quoting Enclave`.

      .. seealso::

         :term:`Architectural Enclaves`

   Intel Provisioning Service
   IPS

      Internet service provided by Intel for EPID-based remote attestation.
      This service provides the corresponding EPID key to the Provisioning
      Enclave on a remote SGX machine.

   Passport model
   Passport attestation model

      :term:`Attestation` protocols can be grouped by which party the
      :term:`attester` relays :term:`attestation evidence` from the TEE to; in
      all protocols, the attestation evidence eventually finds its way to the
      :term:`relying party`. In the passport model, the attester sends
      attestation evidence to the :term:`verifier` and receives back the
      :term:`attestation result`. Then, upon request, the attester forwards the
      attestation result to the :term:`relying party` as a "passport" for
      authentication.

      In contrast, in the :term:`background check model`, the attester sends
      attestation evidence directly to the relying party.

      Currently, Gramine does *not* provide libraries or tools to support the
      passport model. Instead, Gramine supports the background check model.

   Intel Provisioning Certification Service
   PCS

      New internet service provided by Intel for new ECDSA-based remote
      attestation. Enclave provider creates its own internal Attestation Service
      where it caches PKI collateral from Intel's PCS, and the verifier gets the
      certificate chain from the enclave provider to check validity.

      .. seealso::

         :term:`IAS`
            Intel Attestation Service, another Internet service.

   Attestation policy

      A set of rules installed by the :term:`verifier` and/or the :term:`relying
      party` that specifies how the :term:`attestation evidence` is evaluated by
      the :term:`verifier` against :term:`attestation
      endorsements<attestation endorsement>` and reference values. The
      attestation policy also specifies the output format and set of
      :term:`attestation claims<attestation claim>` in the :term:`attestation
      result`.

      For example, :term:`Microsoft Azure Attestation` and :term:`Intel Trust
      Authority` allow users (relying parties) to install their own policies.
      These policies may e.g. disallow any firmware or software versions with
      specific known vulnerabilities.

   Quoting Enclave
   QE

      One of the Architectural Enclaves of the Intel SGX software
      infrastructure. It is part of the :term:`SGX Platform Software`. The
      Quoting Enclave receives an :term:`SGX Report` and produces a
      corresponding :term:`SGX Quote`. The identity of the Quoting Enclave is
      publicly known (it signer, its measurement and its attributes) and is
      vetted by public companies such as Intel (in the form of the certificate
      chain ending in a publicly known root certificate of the company).

      .. seealso::

         :term:`Architectural Enclaves`

   Relying Party

      In the context of remote attestation, the relying party decides whether to
      consider the :term:`attester` a trustworthy peer, based on the analysis of
      the :term:`attestation result` received from the :term:`verifier`.

      In a typical execution flow, the relying party might send the
      :term:`attester` an encrypted input, and after receiving attestation
      results from the verifier, the relying party may then decide to trust the
      attester (TEE) and offer access to the input data by sending a decryption
      key to the attester.

      Another term for relying party is remote trusted party.

      In Gramine's use of attestation, the relying party is typically the
      end-user's client.

   Remote Attestation

      For remote attestation, the attesting SGX enclave collects
      :term:`attestation evidence` in the form of an :term:`SGX Quote` using the
      :term:`Quoting Enclave` (and the :term:`Provisioning Enclave` if
      required). The enclave then may send the collected attestation evidence to
      the local or remote party, which will verify the evidence and confirm the
      authenticity and integrity of the attested enclave. After this, the local
      or remote party trusts the enclave and may establish a secure channel with
      the enclave and send secrets to it.

      .. seealso::

         :doc:`attestation`

   Intel SGX Software Development Kit
   Intel SGX SDK
   SGX SDK
   SDK

      In the context of :term:`SGX`, this means a |~| specific piece of software
      supplied by Intel which helps people write enclaves packed into ``.so``
      files to be accessible like normal libraries (at least on Linux).
      Available together with a |~| kernel module and documentation.

   SGX Enclave Control Structure
   SECS

      .. todo:: TBD

   SGX Quote

      The SGX quote is the proof of trustworthiness of the enclave and is used
      during :term:`Remote Attestation`. The attesting enclave generates the
      enclave-specific :term:`SGX Report`, sends the request to the
      :term:`Quoting Enclave` using :term:`Local Attestation`, and the Quoting
      Enclave returns back the SGX quote with the SGX report embedded in it. The
      resulting SGX quote contains the enclave's measurement, attributes and
      other security-relevant fields, and is tied to the identity of the
      :term:`Quoting Enclave` to prove its authenticity. The obtained SGX quote
      may be later sent to the verifying remote party, which examines the SGX
      quote and gains trust in the remote enclave.

   SGX Report

      The SGX report is a data structure that contains the enclave's measurement,
      signer identity, attributes and a user-defined 64B string. The SGX report
      is generated using the ``EREPORT`` hardware instruction. It is used during
      :term:`Local Attestation`. The SGX report is embedded into the
      :term:`SGX Quote`.

   SGX1

      The original SGX instruction set, without dynamic resource management.

   SGX2

      New SGX instructions and other hardware features that were introduced
      after the release of the original :term:`SGX1` (e.g. :term:`EDMM`).

   Service Provider ID
   SPID

      An identifier provided by Intel, used together with an |~| :term:`EPID`
      API key to authenticate to the :term:`Intel Attestation Service`. You can
      obtain an |~| SPID through Intel's `Trusted Services Portal
      <https://api.portal.trustedservices.intel.com/EPID-attestation>`_.

      See :term:`EPID` for a |~| description of the difference between
      *linkable* and *unlinkable* quotes.

   State Save Area
   SSA

      .. todo:: TBD

   Security Version Number
   SVN

      Each element of the SGX :term:`TCB` is assigned a Security Version Number
      (SVN). For the hardware, these SVNs are referred to collectively as
      CPU_SVN, and for software referred as ISV_SVN. A TCB is considered up to
      date if all components of the TCB have SVNs greater than or equal to a
      threshold published by the author of the component.

   Trusted Execution Environment
   TEE

      A Trusted Execution Environment (TEE) is an environment where the code
      executed and the data accessed are isolated and protected in terms of
      confidentiality (no one has access to the data except the code running
      inside the TEE) and integrity (no one can change the code and its
      behavior).

   Trusted Computing Base
   TCB

      In context of :term:`SGX` this has the usual meaning: the set of all
      components that are critical to security. Any vulnerability in TCB
      compromises security. Any problem outside TCB is not a |~| vulnerability,
      i.e. |~| should not compromise security.

      In context of Gramine there is also a |~| different meaning
      (:term:`Thread Control Block`). Those two should not be confused.

   Trusted Computing Group Device Identifier Composition Engine
   TCG DICE

      TCG DICE is an industry standard developed by the Trusted Computing Group
      organization. The DICE standard (previously called RIoT) mandates
      requirements for hardware-based cryptographic device identity, attestation
      and data encryption.

      The document most relevant to the Gramine project is the `"DICE
      Attestation Architecture" specification
      <https://trustedcomputinggroup.org/resource/dice-attestation-architecture>`__.
      It describes the requirements and flows for :term:`attestation` of a
      :term:`TEE`.

      .. seealso::

         https://datatracker.ietf.org/doc/html/rfc9334 -- Remote ATtestation
         procedureS (RATS) Architecture

   Thread Control Structure
   TCS

      .. todo:: TBD

   Verifier

      In the context of remote attestation, the verifier evaluates the
      :term:`attestation evidence` to decide on the :term:`attester`'s
      trustworthiness.

      Different protocols specify different routes for the verifier to receive
      attestation evidence, see :term:`passport model` and :term:`background
      check model`.

      As a particular example, :term:`Microsoft Azure Attestation` and
      :term:`Intel Trust Authority` are verifiers: they evaluate both the
      hardware and the software trustworthiness, based on evidence reported by
      the platform, such as the version of the firmware on the system or a
      cryptographically signed report that the platform was provisioned with by
      a given vendor.
