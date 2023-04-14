FROM fedora:latest

ENV GOPATH=/var/tmp/go
ENV GOSRC=$GOPATH/src/github.com/containers/oci-seccomp-bpf-hook
ENV CIRRUS_WORKING_DIR=$GOSRC \
    PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:$GOPATH/bin:$GOSRC/bin \
    GOCACHE=/root/.cache/go-build \
    CONTAINER=true

RUN dnf update -y && \
    dnf clean -y all && \
    rm -rf /var/cache/dnf

ADD / $GOSRC

WORKDIR $GOSRC

RUN ./contrib/cirrus/setup.sh && \
    dnf clean -y all && \
    rm -rf /var/cache/dnf

RUN cd / && rm -rf $GOSRC && mkdir -p $GOSRC

VOLUME $GOSRC
