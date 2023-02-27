FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-distutils \
    python3-setuptools

COPY scripts/get-python-platlib.py /get-python-platlib.py
RUN mkdir -p "$(python3 /get-python-platlib.py /usr/local)"
