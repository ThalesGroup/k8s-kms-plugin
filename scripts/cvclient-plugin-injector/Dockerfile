FROM debian:unstable
ARG cvclientpackage="cvclient-min.tar.gz"
ADD ${cvclientpackage} /opt/cvclient/
ADD inject.sh /inject-pkcs11-driver

ENTRYPOINT ["/inject-pkcs11-driver"]
