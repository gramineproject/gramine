FROM almalinux:9

RUN dnf install -y \
    'dnf-command(config-manager)' \
    epel-release \
    git \
    jq \
    rpm-build
RUN dnf config-manager --set-enabled -y crb

# NOTE: COPY invalidates docker cache when source file changes,
# so `dnf builddep` will rerun if dependencies change, despite no change
# in dockerfile.
COPY gramine.spec /gramine.spec
RUN dnf builddep -y /gramine.spec
