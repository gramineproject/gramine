Code singing and release manual
===============================

.. _code-signing:

Code signing
------------

.. note::

    “Code signing” is not to be confused with “signing off” your commits.

    “Signing off” is (in our project) a |~| legal device for a |~| sort of
    signature by which you assert that you are holding copyrights to the code
    you're submitting (or your're authorized by copyright holder to submit the
    code). “Signing off” is done by writing ``Signed-off-by:`` line to the
    commit message (maybe using :command:`git commit -s`) and does not carry
    a |~| separate cryptographic signature. For details, please read
    :doc:`DCO/index`, and keep in mind that in other projects meaning of the
    ``Signed-off-by:`` line might be different.

    “Code signing” refers to the process of cryptographically signing your
    contributions (commits and tags), so other people are able to mathematically
    prove that the contribution came from the holder of a |~| particular
    cryptographic key. It has no legal meaning. It can be done using
    :command:`git commit -S` or by configuring :program:`git` (see below).

Generating key
^^^^^^^^^^^^^^

First, you need to generate your own key pair using :program:`gpg`. The key
needs to be "sign only"! Otherwise, if you also add encrypt capability, people
will add your key to their :abbr:`MUA (Mail User Agent)`\ s and will encrypt
e-mail messages to you using code signing key. This is not desired, the key
generated for the purpose of code signing should not be used in any other
context (e.g. e-mail or signing code in other projects).

In user ID, please write your name and comment saying that the key is meant for
code signing in this project.

The key needs to be RSA (at least 3072 to match overall security level in SGX)
or Curve25519. 25519 keys are preferred, because they are smaller and faster to
use. In some versions of :program:`gpg` you need to use ``--full-gen-key
--expert`` to be able to choose ECC keys.

.. code-block:: none

    % gpg --full-gen-key --expert
    gpg (GnuPG) 2.2.27; Copyright (C) 2021 Free Software Foundation, Inc.
    This is free software: you are free to change and redistribute it.
    There is NO WARRANTY, to the extent permitted by law.

    Please select what kind of key you want:
       (1) RSA and RSA (default)
       (2) DSA and Elgamal
       (3) DSA (sign only)
       (4) RSA (sign only)
       (7) DSA (set your own capabilities)
       (8) RSA (set your own capabilities)
       (9) ECC and ECC
      (10) ECC (sign only)
      (11) ECC (set your own capabilities)
      (13) Existing key
      (14) Existing key from card
    Your selection? 10
    Please select which elliptic curve you want:
       (1) Curve 25519
       (3) NIST P-256
       (4) NIST P-384
       (5) NIST P-521
       (6) Brainpool P-256
       (7) Brainpool P-384
       (8) Brainpool P-512
       (9) secp256k1
    Your selection? 1
    Please specify how long the key should be valid.
             0 = key does not expire
          <n>  = key expires in n days
          <n>w = key expires in n weeks
          <n>m = key expires in n months
          <n>y = key expires in n years
    Key is valid for? (0)
    Key does not expire at all
    Is this correct? (y/N) y

    GnuPG needs to construct a user ID to identify your key.

    Real name: Wojciech Porczyk
    Email address: woju@invisiblethingslab.com
    Comment: Gramine code signing key
    You selected this USER-ID:
        "Wojciech Porczyk (Gramine code signing key) <woju@invisiblethingslab.com>"

    Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit? o
    We need to generate a lot of random bytes. It is a good idea to perform
    some other action (type on the keyboard, move the mouse, utilize the
    disks) during the prime generation; this gives the random number
    generator a better chance to gain enough entropy.
    gpg: /home/user/.gnupg/trustdb.gpg: trustdb created
    gpg: key 044D9664E7A77E16 marked as ultimately trusted
    gpg: directory '/home/user/.gnupg/openpgp-revocs.d' created
    gpg: revocation certificate stored as '/home/user/.gnupg/openpgp-revocs.d/9C4D27D9157EF771A4283926044D9664E7A77E16.rev'
    public and secret key created and signed.

    pub   ed25519 2024-02-22 [SC]
          9C4D27D9157EF771A4283926044D9664E7A77E16
    uid                      Wojciech Porczyk (Gramine code signing key) <woju@invisiblethingslab.com>

.. yes, this is actual log from generating my own key!

Submitting key to GitHub
^^^^^^^^^^^^^^^^^^^^^^^^

https://docs.github.com/en/authentication/managing-commit-signature-verification/adding-a-gpg-key-to-your-github-account#adding-a-gpg-key

Setting up git
^^^^^^^^^^^^^^

*(Substitute key ID for your own key. The following example matches key ID from
the example generation listing.)*

.. code-block:: sh

    git config --global commit.gpgsign true
    git config --global user.signingkey 9C4D27D9157EF771A4283926044D9664E7A77E16

If you are using Split GPG feature of Qubes OS
(https://www.qubes-os.org/doc/split-gpg/#using-git-with-split-gpg):

.. code-block:: sh

    git config --global gpg.program qubes-gpg-client-wrapper

and remember to set ``QUBES_GPG_DOMAIN`` environment variable in your shell
config file.

Release process
---------------

Create new checklist issue (fill all ``<variable>`` before submitting):

.. new-issue:: Release <version> checklist

    - [ ] create release PRs (@<owner>)
        - gramine: #
        - gramine-scaffolding: #
        - contrib: #
    - [ ] draft release notes (@<owner>)
    - [ ] draft blogpost (@<owner>)
    - [ ] draft #community announcement (@<owner>)
    - [ ] update installation instructions (if a distro was released since last release) (@<owner>)

    iterate (update version, build and upload unstable packages)

    final stretch:
    - [ ] get QA signoff (@<owner>)
    - [ ] approve PRs (@<owner>)
    - [ ] update version to final and push commits (@<owner>)
    - [ ] build final packages (@<owner>)
    - [ ] upload packages to release notes (@<owner>)
    - [ ] push tag (@<owner>)
    - [ ] switch release notes to pushed tag (@<owner>)
    - [ ] merge PR (@<owner>)
    - [ ] publish release notes (@<owner>)
    - [ ] publish blogpost (@<owner>)
    - [ ] publish on #community (@<owner>)

Create a PR
^^^^^^^^^^^

.. code-block:: sh

    git checkout -b <owner>/release-<X.Y>
    scripts/release.sh <X.Y>~rc1
    git push -u origin <owner>/release-<X.Y>
    firefox https://github.com/gramineproject/gramine/pull/new/<owner>/release-<X.Y>

Then set the PR on reviewable.io to be reviewed commit-by-commit.

Update version in the PR
^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: sh

    git reset --hard HEAD~
    scripts/release.sh X.Y~rcN
    git push --force

Create a tag
^^^^^^^^^^^^

.. code-block:: sh

    git tag -m "Gramine <X.Y>" v<X.Y> HEAD~
    git push v<X.Y>
