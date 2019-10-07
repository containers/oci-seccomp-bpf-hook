#!/bin/bash

set -e

source $(dirname $0)/lib.sh

cd $GOSRC

# Only Output on Error wrapper
install_ooe

case "$OS_RELEASE_ID" in
    fedora)
        INSTALL_COMMAND='dnf install -y'
        LIST_COMMAND='rpm -q --qf=%{N}-%{V}-%{R}-%{ARCH}\n'
        # Installed AND separetly querried/displayed
        CRITICAL_PKGS=(\
            bcc-devel \
            conmon \
            container-selinux \
            containers-common \
            crun \
            golang \
            libseccomp \
            podman \
            runc \
        )
        # These will not be displayed, unless there is an error
        INSTALL_PACKAGES=(\
            "${CRITICAL_PKGS[@]}" \
            autoconf \
            automake \
            bash-completion \
            bats \
            bridge-utils \
            btrfs-progs-devel \
            bzip2 \
            containers-common \
            device-mapper-devel \
            emacs-nox \
            file \
            findutils \
            fuse3 \
            fuse3-devel \
            gcc \
            git \
            glib2-devel \
            glibc-static \
            gnupg \
            go-md2man \
            gpgme-devel \
            iproute \
            iptables \
            jq \
            kernel-headers \
            libassuan-devel \
            libcap-devel \
            libmsi1 \
            libnet \
            libnet-devel \
            libnl3-devel \
            libseccomp-devel \
            libselinux-devel \
            libtool \
            libvarlink-util \
            lsof \
            make \
            msitools \
            nmap-ncat \
            ostree \
            ostree-devel \
            pandoc \
            procps-ng \
            protobuf \
            protobuf-c \
            protobuf-c-devel \
            protobuf-devel \
            protobuf-python \
            python \
            python3-dateutil \
            python3-psutil \
            python3-pytoml \
            selinux-policy-devel \
            unzip \
            vim \
            which \
            xz \
            zip \
        )
        # Some small differences between 30 and 31
        case "$OS_RELEASE_VER" in
            30)
                INSTALL_PACKAGES+=(\
                    atomic-registries \
                    golang-github-cpuguy83-go-md2man \
                    python2-future \
                    runc \
                )
                ;;
            31)
                INSTALL_PACKAGES+=(crun)
                ;;
            *)
                bad_os_id_ver ;;
        esac
        echo "Enabling updates-testing repository"
        ooe.sh $INSTALL_COMMAND 'dnf-command(config-manager)'
        ooe.sh dnf config-manager --set-enabled updates-testing
        echo "Upgrading all packages"
        ooe.sh dnf update -y
        ;;
    ubuntu)
        export DEBIAN_FRONTEND="noninteractive"
        INSTALL_COMMAND="apt-get -qq --yes"
        LIST_COMMAND='dpkg-query --show --showformat=${Package}-${Version}-${Architecture}\n'
        # TODO: Only F30 supported at the moment
        CRITICAL_PKGS=()  # TODO
        INSTALL_PACKAGES=()  # TODO
        apt-get -qq --yes update  # download repo data
        echo "Upgrading all packages"
        apt-get -qq --yes upgrade
        bad_os_id_ver
        ;;
    *)
        bad_os_id_ver
        ;;
esac

echo "Installing required packages (could take a handful of minutes)"
ooe.sh $INSTALL_COMMAND ${INSTALL_PACKAGES[@]}

if [[ "$OS_RELEASE_ID" == "fedora" ]] && [[ -r "/usr/libexec/podman/conmon" ]]
then
    echo "Warning: Working around podman 1.5 w/ embedded conmon."
    rm -vf '/usr/libexec/podman/conmon'
fi

# Some variables change after package install
source $(dirname $0)/lib.sh

echo "Building/Installing tooling"
ooe.sh make install.tools

echo "Names and versions of critical packages"
NOT_INSTALLED_RE='(package .+ is not installed)|(no packages found matching .+)'
$LIST_COMMAND ${CRITICAL_PKGS[@]} | sed -r -e "s/$NOT_INSTALLED_RE/ > > \0/" | sort
