Scaffolding For Gramine
=======================

The Scaffolding for Gramine (SCAG) tool meticulously transforms your
application into a Graminized Docker image, encapsulating both your
application and the Gramine Library OS. The primary objective of the
Scaffolding project is to expedite the process of safeguarding applications
against malicious hosts.

Setting itself apart from alternative solutions (like GSC), SCAG doesn't
transform a Docker image, instead it generates a whole Docker image from
the given projects. During the build process the required Dockerfile,
manifest file, and other required configuration files are generated
automatically for the user.

To speed up the process, SCAG offers a single command - ``scag-quickstart``.
This tool also guides user interactively through the entire process of
"graminizing" application, from setting up the project to building it, and
finally running it.  For more advanced usage of SCAG, users are encouraged
to refer to the documentation.

All web-based frameworks, such as Express.js and Flask, are preconfigured
to operate behind a web server (nginx), with SSL/TLS and the RA-TLS extension.

Note that the SCAG tool is split from core Gramine and is hosted here:

- https://github.com/intel/ScaffoldingForGramine -- GitHub repository,
- https://gramine-scaffolding.readthedocs.io/en/latest/ -- documentation.
