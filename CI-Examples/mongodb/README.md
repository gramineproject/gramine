# MongoDB example

This directory contains an example for running MongoDB in Gramine, including the
Makefile and a template for generating the manifest.

# Generating the manifest

## Installing prerequisite

Please run the following commands to install MongoDB 6.0 Community Edition on Ubuntu 20.04:

1. Import the public key used by the package management system:

    1. From a terminal, install `gnupg` and `curl` if they are not already available:
       ```
       sudo apt-get install gnupg curl
       ```

    2. Issue the following command to import the MongoDB public GPG Key from
       https://pgp.mongodb.com/server-6.0.asc:
       ```
       curl -fsSL https://pgp.mongodb.com/server-6.0.asc | \
           sudo gpg -o /usr/share/keyrings/mongodb-server-6.0.gpg --dearmor
        ```

2. Create a list file for MongoDB:
   ```
   echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-6.0.gpg ] \
       https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/6.0 multiverse" | \
       sudo tee /etc/apt/sources.list.d/mongodb-org-6.0.list
   ```

3. Reload local package database:
   ```
   sudo apt-get update
   ```

4. Install the MongoDB packages:
   ```
   sudo apt-get install -y mongodb-org
   ```

## Building for Linux

Run `make` (non-debug) or `make DEBUG=1` (debug) in the directory.

## Building for SGX

Run `make SGX=1` (non-debug) or `make SGX=1 DEBUG=1` (debug) in the directory.

# Running MongoDB with Gramine

Here's an example of running MongoDB under Gramine (note that command-line options are hardcoded in
the manifest file):

Without SGX:
```
gramine-direct mongod
```

With SGX:
```
gramine-sgx mongod
```

# Testing client connection

Run the below commands from a new terminal:

- `mongosh` to connect a client to MongoDB server.
- `test> exit` to disconnect the client.
