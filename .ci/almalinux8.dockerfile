FROM almalinux:8

RUN dnf install -y \
    'dnf-command(config-manager)' \
    epel-release \
    gcc-toolset-14-gcc \
    gcc-toolset-14-gcc-c++ \
    git \
    jq \
    rpm-build
RUN dnf config-manager --set-enabled -y powertools

ENV PATH="/opt/rh/gcc-toolset-14/root/usr/bin:${PATH}"

# NOTE: COPY invalidates docker cache when source file changes,
# so `dnf builddep` will rerun if dependencies change, despite no change
# in dockerfile.
COPY gramine.spec /gramine.spec
RUN dnf builddep -y /gramine.spec
