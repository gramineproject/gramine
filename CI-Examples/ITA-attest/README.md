# A Minimum Containerized & Graminized Attestable Application

This example takes advantage of GSC tool's capability
to wrap a common application container with Gramine-SGX.

It shows a way to attest a SGX wrapped application with Intel Trust Authority (TIA).

## Quick Start

- Prerequisites

    1. A SGX2 enabled Linux box

        ```sh
        grep sgx /proc/cpuinfo && ls -l /dev/sgx*
        sudo dmesg | grep -i sgx
        ````

    2. In-kernel SGX driver

        ```sh
        # Linux kernel v5.15 or greater
        uname -a
        cat /etc/os-release
        ```

    3. AESMD service up and running

        Please refer to the repo of Intel SGX SDK
        [Linux SGX](https://github.com/intel/linux-sgx),
        [Installation Guide](https://download.01.org/intel-sgx/sgx-dcap/1.16/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf),
        [Quick Install Guide](https://www.intel.com/content/www/us/en/developer/articles/guide/intel-software-guard-extensions-data-center-attestation-primitives-quick-install-guide.html)
        and make sure it functions correctly.

        ```sh
        # check status
        systemctl status aesmd
        journalctl -u aesmd
        ```

    4. Docker

        Please refer to [Install Docker Engine on Ubuntu](https://docs.docker.com/engine/install/ubuntu/)

    5. Others

        ```sh
        sudo apt install python3-pip
        pip3 install docker
        pip3 install tomli
        pip3 install tomli_w

        # Fixup urllib3 v2 incompatibility
        # https://github.com/docker/docker-py/issues/3113
        pip3 uninstall requests
        pip3 install -Iv requests==2.28.1

        sudo apt install pv
        ```

    6. on Azure CVM

        The PCCS should not be installed on Azure CVM; instead deploying its platform specific quoting data provider.

        a. Download and install the [Azure-DCAP-Client](https://github.com/Microsoft/Azure-DCAP-Client/releases) corresponding to Linux distro.

        b. Otherwise, build from source code and then install it

          Please refer to [Azure-DCAP-Client](https://github.com/microsoft/Azure-DCAP-Client)

        Note that all conflicting quoting data providers should be uninstalled, such as libsgx-dcap-default-qpl.

        Regarding AESMD service, it still need to be deployed on Azure CVM as well, because the underlying Gramine-SGX wrapper relies on it to function at runtime.

- Configuration

    An ITA API key is required from [Intel Trust Authority](https://trustauthority.intel.com/).

    Run the following command to generate an initial `gramine.manifest` file

    ```sh
    make ITA_API_KEY=<ITA API Key> init-manifest
    ```

    In the generated file `gramine.manifest`, you can add additional settings
    which are supported by [Gramine-SGX](https://gramine.readthedocs.io/en/stable/manifest-syntax.html)

    Please note that those settings will be measured together with the SGX application, so any changes to this configuration file will require rebuilding it.

- Run a workflow of attestation token retrieval; build with SGX enabled:

    ```sh
    make clean
    make

    # test the plain app
    make test-app

    # test the containerized & graminized app
    make test-gsc-app

    # deploy it to Azure VM
    make AZURESSHPRVKEYFILE=<ssh private key file> AZURESSHIP=<ssh ip> deploy
    ```

    Please note that all previously generated docker images, including dangling ones, need to be **manually removed** before rebuilding.

- Check the attestation token as needed

    ```sh
    # install this tool for JWT decode
    sudo snap install jwt-decode

    # decode the header of attestation token
    jwt-decode.header "<paste attestation token here>"

    # decode the payload of attestation token
    jwt-decode.payload "<paste attestation token here>"
    ```
