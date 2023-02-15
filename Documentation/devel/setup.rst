Development setup
=================

Editor config
-------------

For contributors, we strongly suggest using the following configuration
according to your editors.

Emacs configuration
^^^^^^^^^^^^^^^^^^^

No change needed. See :file:`.dir-locals.el`.

Vim configuration
^^^^^^^^^^^^^^^^^

Please add the following script to the end of your :file:`~/.vimrc`,
or place in :file:`~/.vim/after/ftplugin/c.vim` if you have other plugins.

.. code-block:: vim

   let dirname = expand('%:p:h')
   let giturl = system('cd '.dirname.'; git config --get remote.origin.url 2>/dev/null')
   if giturl =~ 'gramineproject/gramine'
      set textwidth=100 tabstop=4 softtabstop=4 shiftwidth=4 expandtab
   endif

   au BufRead,BufNewFile *.rst imap <A-Space> <Space>\|~\|<Space>
   au BufRead,BufNewFile *.rst set textwidth=80

.. warning::

   Due to security concerns, we do not suggest using Vim modelines or
   :file:`.exrc`.

meson devenv
------------

We have some barely functioning ``meson devenv``. There are limitations:

- manifests rendered inside devenv cannot be used outside and *vice versa* (i.e.
  if you're doing ``CI-Examples/``, you need to ``make clean`` each time you
  go in or out of devenv;

- the only library in ``{{ runtimedir }}`` is libc (either glibc or musl) --
  this means you can't run RA-TLS examples that link against
  ``mbedtls_gramine``;

- ``pkg-config`` is not tested (``-uninstalled.pc``), possibly might be made to
  work given enough effort, which was not yet expended

.. highlight:: sh

   meson setup build/ -Dsgx=enabled -Ddirect=enabled
   meson compile -C build/
   meson devenv -C build/
   cd ../CI-Examples/helloworkd
   make clean
   make
   gramine-direct helloworld

Then each time you change source, you just ``meson compile`` in another console
and your original devenv is still valid (if you change ``meson.build``, you may
need to reopen devenv).

.. seealso::

   meson devenv command
      https://mesonbuild.com/Commands.html#devenv
