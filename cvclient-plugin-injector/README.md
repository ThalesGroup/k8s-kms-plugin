# Thales PKCS11 Client Library Injector.

The KMS plugin itself is redistributable, we can include it
in the GKE OnPrem Container Repository, and this repository can
be a publicly available.

However, the Thales Client Library is proprietary software, and not publicly
redistributable. This client library is a dependency for the KMS plugin
when the HSM is being used.

The Docker image built here is made available separately to those customers
licensed to use the client package.

# Building the container.

Running ./build.sh performs the following steps.

1. Download the cvclient-min.tar.gz from an external location (eg: a gcs
   bucket), and save it to this directory.

2. docker build -t thales-injector:v1

3. docker push to the repository.
