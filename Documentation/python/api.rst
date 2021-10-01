.. default-domain:: py
.. highlight:: py

Python API
==========

Introduction
------------

We have very beautiful and very enterprise API, used for enterprise signing and
attestation. See especially our :func:`~graminelibos.manifest.render` function!

Examples
--------

To render a |~| manifest::

   import graminelibos.manifest

   print(graminelibos.manifest.render('blablabla = "{{ foo }}"', {'foo': 123}))

API Reference
-------------

.. autofunction:: graminelibos.manifest.render
