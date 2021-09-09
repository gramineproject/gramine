# Gramine Attestation Inside AKS cluster

This guide demonstrates how Gramine DCAP attestation quote can be generated and verified from
within an AKS cluster. Here, we provide an end-to-end example to help Cloud Solution Providers
integrate gramine’s RA-TLS attestation and secret provisioning feature with a confidential compute
cluster managed by Azure Kubernetes Service. The necessary reference wrappers that will enable
gramine to use AKS components such as the AESMD and quote provider libraries are contributed.
A microservice deployment is also provided for the RA-TLS verifier module that can be readily
deployed to the AKS cluster.

## Create client and server images for gramine attestation samples

This demonstration is created for ``gramine/Examples/ra-tls-secret-prov`` sample.

- Steps to create ra-tls-secret-prov server image for AKS:

```sh
Please refer gramine/Tools/gsc/images/gramine-aks-attestation/aks-secret-prov-server.dockerfile
```

- Steps to create ra-tls-secret-prov client (min client) gsc image for AKS:

```sh
Please refer gramine/Tools/gsc/images/gramine-aks-attestation/aks-secret-prov-client.dockerfile
Note: We recommend deploying gsc images on Ubuntu with Linux kernel version 5.11 or higher.
For kernel version lower than 5.11, please uncomment line9 at gsc/templates/apploader.template.
```

## Deploy both client and server images inside AKS confidential compute cluster

AKS confidential compute cluster can be created using following
[link](https://docs.microsoft.com/en-us/azure/confidential-computing/confidential-nodes-aks-get-started).

Gramine performs out-of-proc mode DCAP quote generation. Out-of-proc mode quote generation requires aesmd
service. To fulfill this requirement, AKS provides
[sgxquotehelper daemonset](https://docs.microsoft.com/en-us/azure/confidential-computing/confidential-nodes-out-of-proc-attestation).
This feature exposes aesmd service for the container node. The service will internally connect with
az-dcap-client to fetch the platform collateral required for quote generation. In this demo, the
``aks-secret-prov-client-deployment.yaml`` uses aesmd service exposed by AKS with the help of
sgxquotehelper plugin.

In the ra-tls-secret-prov example, the client will generate out-of-proc mode sgx quote that will be
embedded inside RA-TLS certificate. On receiving the quote, the server will internally verify it
using libsgx-dcap-quote-verify library via az-dcap-client library. Here,
``aks-secret-prov-server-deployment.yaml`` will deploy a ra-tls-secret-prov server container inside
 AKS cluster.

**Deployment**<br>

```sh
$ kubectl apply -f aks-secret-prov-server-deployment.yaml
```

Once the server container is in running state, start the client container as shown below

```sh
$ kubectl apply -f aks-secret-prov-client-deployment.yaml
```

At this stage, a successful RA-TLS verification would be completed, and the secrets have been
provisioned from the server to the client container.

## Steps to verify successful quote generation and quote verification using logs

Verify the client job is completed

```sh
$ kubectl get pods
```
Receive logs to verify the secret has been provisioned to the client

```sh
$ kubectl logs -l app=gsc-ra-tls-secret-prov-client --tail=50
```

**Expected Output**<br>

--- Received secret = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'

Delete both client and server containers

```sh
$ kubectl delete -f aks-secret-prov-server-deployment.yaml
$ kubectl delete -f aks-secret-prov-client-deployment.yaml
```
