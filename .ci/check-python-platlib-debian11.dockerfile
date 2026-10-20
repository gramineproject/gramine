FROM debian:bullseye-backports

ENV DEBIAN_FRONTEND=noninteractive

RUN find /etc/apt -type f \( -name '*.list' -o -name '*.sources' \) \
    -exec sed -i '/bullseye-backports/s|deb.debian.org/debian|archive.debian.org/debian|g' {} + \
    && apt-get update && apt-get install -y \
    python3 \
    python3-distutils \
    python3-setuptools

COPY scripts/get-python-platlib.py /get-python-platlib.py
RUN mkdir -p "$(python3 /get-python-platlib.py /usr/local)"
