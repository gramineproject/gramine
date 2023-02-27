FROM almalinux:9

COPY scripts/get-python-platlib.py /get-python-platlib.py
RUN mkdir -p "$(python3 /get-python-platlib.py /usr/local)"
