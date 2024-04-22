.. highlight:: none

.. _verifying-cryptographic-signatures:

Verifying cryptographic signatures
==================================

Verifying packages
------------------

APT repositories (for Debian and Ubuntu) are signed with the following GPG key::

    pub   ed25519 2021-02-17 [SC]
        EA3C2D624681AC968521587A5EE1171912234070
    uid           Gramine Project signing key (2021)
    uid           Graphene Library OS signing key (2021)

RPM packages (for RHEL derivatives) are signed with the following key::

    pub   rsa4096 2021-10-29 [SC]
          F3FFBE5FC0477DB46E4851E737B04F03659B87AF
    uid           Gramine Project signing key, RPM (2021)

Verification of the signatures for the packages happens automatically during
repository metadata update or package installation process, and skipping this
verification needs to be done intentionally. :ref:`Package installation
instructions <install-gramine-packages>` describe downloading those keys and
copying them to system's directory, but if you want to trust the key long-term,
you should download this key only once, verify it and keep local, trusted copy
yourself (for example by checking in the file into version control system). For
each reinstall, you should then copy the key from your local store (for example,
in ``Dockerfile`` you should ``COPY`` it, not ``RUN wget -O ...``).

Verifying releases (git tags) and commits
-----------------------------------------

Releases of Gramine are marked with `signed tags
<https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work>`__ by Wojtek
Porczyk::

    pub   ed25519 2024-02-22 [SC]
        9C4D27D9157EF771A4283926044D9664E7A77E16
    uid           Wojciech Porczyk (Gramine code signing key) <woju@invisiblethingslab.com>

(woju's first name is „Wojciech” /ˈvɔj.t͡ɕɛx/; „Wojtek” /ˈvɔj.tɛk/ is a |~|
pronounceable diminutive).

The key is available in ``keys/`` subdirectory of the main project's tree.

To verify a |~| tag, you need to import this key into your local trust store:

.. code-block:: sh

    git clone https://github.com/gramineproject/gramine.git
    gpg --import gramine/keys/woju.asc

Then check the key fingerprint. After ensuring the key is correct, you can mark
it as trusted.

Trusting the key directly
^^^^^^^^^^^^^^^^^^^^^^^^^

If you don't have your own PGP key pair, you can mark the key as ultimately
trusted::

    % gpg --edit-key 9C4D27D9157EF771A4283926044D9664E7A77E16
    gpg (GnuPG) 2.2.27; Copyright (C) 2021 Free Software Foundation, Inc.
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.


    pub  ed25519/044D9664E7A77E16
        created: 2024-02-22  expires: never       usage: SC
        trust: full          validity: unknown
    [ unknown] (1). Wojciech Porczyk (Gramine code signing key) <woju@invisiblethingslab.com>

    gpg> trust
    pub  ed25519/044D9664E7A77E16
        created: 2024-02-22  expires: never       usage: SC
        trust: full          validity: unknown
    [ unknown] (1). Wojciech Porczyk (Gramine code signing key) <woju@invisiblethingslab.com>

    Please decide how far you trust this user to correctly verify other users' keys
    (by looking at passports, checking fingerprints from different sources, etc.)

    1 = I don't know or won't say
    2 = I do NOT trust
    3 = I trust marginally
    4 = I trust fully
    5 = I trust ultimately
    m = back to the main menu

    Your decision? 5
    Do you really want to set this key to ultimate trust? (y/N) y

    pub  ed25519/044D9664E7A77E16
        created: 2024-02-22  expires: never       usage: SC
        trust: ultimate      validity: unknown
    [ unknown] (1). Wojciech Porczyk (Gramine code signing key) <woju@invisiblethingslab.com>
    Please note that the shown key validity is not necessarily correct
    unless you restart the program.

    gpg> save
    Key not changed so no update needed.

Note it needs to be ``5 = I trust ultimately``, not even ``4 = I trust fully``.
The description of the difference between those options is beyond the scope of
this document.

.. "beyond the scope" in this context is a politically-correct understatement

Trusting the key using local private key
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you happen to have your own PGP key pair, you can choose to sign the key with
local signature. This is the procedure supported by GPG tool, because it fits
“web of trust” model::

    % gpg --edit-key 9C4D27D9157EF771A4283926044D9664E7A77E16
    gpg (GnuPG) 2.2.27; Copyright (C) 2021 Free Software Foundation, Inc.
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.
    
    
    pub  ed25519/044D9664E7A77E16
         created: 2024-02-22  expires: never       usage: SC  
         trust: unknown       validity: unknown
    [ unknown] (1). Wojciech Porczyk (Gramine code signing key) <woju@invisiblethingslab.com>
    
    gpg> ltnrsign
    
    pub  ed25519/044D9664E7A77E16
         created: 2024-02-22  expires: never       usage: SC  
         trust: unknown       validity: unknown
     Primary key fingerprint: 9C4D 27D9 157E F771 A428  3926 044D 9664 E7A7 7E16
    
         Wojciech Porczyk (Gramine code signing key) <woju@invisiblethingslab.com>
    
    Please decide how far you trust this user to correctly verify other users' keys
    (by looking at passports, checking fingerprints from different sources, etc.)
    
      1 = I trust marginally
      2 = I trust fully
    
    Your selection? 2
    
    Please enter the depth of this trust signature.
    A depth greater than 1 allows the key you are signing to make
    trust signatures on your behalf.
    
    Your selection? 1
    
    Please enter a domain to restrict this signature, or enter for none.
    
    Your selection? 
    
    Are you sure that you want to sign this key with your
    key "TEST DO NOT USE" (0000000000000000)
    
    The signature will be marked as non-exportable.
    
    The signature will be marked as non-revocable.
    
    Really sign? (y/N) y
    
    gpg> save
    % gpg -k 9C4D27D9157EF771A4283926044D9664E7A77E16
    gpg: checking the trustdb
    gpg: marginals needed: 3  completes needed: 1  trust model: pgp
    gpg: depth: 0  valid:   1  signed:   1  trust: 0-, 0q, 0n, 0m, 0f, 1u
    gpg: depth: 1  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 1f, 0u
    pub   ed25519 2024-02-22 [SC]
          9C4D27D9157EF771A4283926044D9664E7A77E16
    uid           [  full  ] Wojciech Porczyk (Gramine code signing key) <woju@invisiblethingslab.com>

.. no, I don't have "0000000000000000" key

If you know what you're doing, you can use another signing command in place of
``ltnrsign``.

Trusting the key directly (from scripts)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: sh

    echo 9C4D27D9157EF771A4283926044D9664E7A77E16:6: | gpg --import-ownertrust

Note this option is not very well documented.

Verifying tags
^^^^^^^^^^^^^^

Use either :command:`git tag --verify <tag>` or :command:`git verify-tag <tag>`
to verify tags::

    % git tag --verify v1.6.2
    object a971e30f3430b4b8079ec42f5d035ced68130bdc
    type commit
    tag v1.6.2
    tagger Wojtek Porczyk <woju@invisiblethingslab.com> 1710237857 +0100

    Gramine 1.6.2
    gpg: Signature made Tue 12 Mar 2024 11:04:18 AM CET
    gpg:                using EDDSA key 9C4D27D9157EF771A4283926044D9664E7A77E16
    gpg: Good signature from "Wojciech Porczyk (Gramine code signing key) <woju@invisiblethingslab.com>" [full]

::

    % git verify-tag v1.6.2
    gpg: Signature made Tue 12 Mar 2024 11:04:18 AM CET
    gpg:                using EDDSA key 9C4D27D9157EF771A4283926044D9664E7A77E16
    gpg: Good signature from "Wojciech Porczyk (Gramine code signing key) <woju@invisiblethingslab.com>" [full]

If you fail to mark the key as trusted, you will see instead::

    % git tag --verify v1.6.2
    object a971e30f3430b4b8079ec42f5d035ced68130bdc
    type commit
    tag v1.6.2
    tagger Wojtek Porczyk <woju@invisiblethingslab.com> 1710237857 +0100

    Gramine 1.6.2
    gpg: Signature made Tue 12 Mar 2024 11:04:18 AM CET
    gpg:                using EDDSA key 9C4D27D9157EF771A4283926044D9664E7A77E16
    gpg: checking the trustdb
    gpg: no ultimately trusted keys found
    gpg: Good signature from "Wojciech Porczyk (Gramine code signing key) <woju@invisiblethingslab.com>" [unknown]
    gpg: WARNING: This key is not certified with a trusted signature!
    gpg:          There is no indication that the signature belongs to the owner.
    Primary key fingerprint: 9C4D 27D9 157E F771 A428  3926 044D 9664 E7A7 7E16

Which is **NOT a successful verification**, because the key might be
different. Anyone can generate a |~| key with some first and last name, so
unless you check the fingerprint every single time, you should not trust this
verification with the warning.

Verifying commits
^^^^^^^^^^^^^^^^^

You can use ``--show-signature`` option to ``git log`` command, or ``git
verify-commit`` standalone command::

    % git log v1.6.2 --show-signature
    commit a971e30f3430b4b8079ec42f5d035ced68130bdc (tag: v1.6.2)
    gpg: Signature made Tue 12 Mar 2024 09:34:37 AM CET
    gpg:                using EDDSA key 9C4D27D9157EF771A4283926044D9664E7A77E16
    gpg: Good signature from "Wojciech Porczyk (Gramine code signing key) <woju@invisiblethingslab.com>" [ultimate]
    Author: Wojtek Porczyk <woju@invisiblethingslab.com>
    Date:   Mon Mar 11 10:26:34 2024 +0100
    
        Bump version to 1.6.2
    
        Signed-off-by: Wojtek Porczyk <woju@invisiblethingslab.com>
    
    [...]

::

    % git verify-commit a971e30f3430b4b8079ec42f5d035ced68130bdc
    gpg: Signature made Tue 12 Mar 2024 09:34:37 AM CET
    gpg:                using EDDSA key 9C4D27D9157EF771A4283926044D9664E7A77E16
    gpg: Good signature from "Wojciech Porczyk (Gramine code signing key) <woju@invisiblethingslab.com>" [ultimate]
