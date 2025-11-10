FROM registry.access.redhat.com/ubi9/ubi-micro:latest AS micro

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest AS base-installer
# Only set variables or install packages that need to end up in the
# final container here.
USER root

COPY --from=micro / /mnt/rootfs/

# Common microdnf options for installroot operations
RUN set -ex \
	&& MICRODNF_OPTS="--installroot=/mnt/rootfs --config=/etc/dnf/dnf.conf --noplugins --setopt=reposdir=/etc/yum.repos.d --setopt=cachedir=/var/cache/dnf --setopt=varsdir=/etc/dnf/vars --setopt=tsflags=nodocs" \
	&& microdnf $MICRODNF_OPTS -y module enable nginx:1.24 \
	&& microdnf $MICRODNF_OPTS -y update \
	&& microdnf $MICRODNF_OPTS --setopt=install_weak_deps=0 -y install \
	dnsmasq \
	file \
	libpq \
	memcached \
	nginx \
	libjpeg-turbo \
	openldap \
	openssl \
	python3.12 \
	glibc-langpack-en \
	glibc-minimal-langpack \
	&& microdnf $MICRODNF_OPTS -y reinstall tzdata \
	&& microdnf $MICRODNF_OPTS -y clean all \
	&& rm -rf /var/cache/yum


FROM registry.access.redhat.com/ubi9/ubi-micro:latest AS base

USER root

# Environment variables
ENV PYTHON_VERSION=3.12 \
	PYTHONUNBUFFERED=1 \
	PYTHONIOENCODING=UTF-8 \
	LC_ALL=en_US.UTF-8 \
	LANG=en_US.UTF-8 \
	TZ=UTC \
	CNB_STACK_ID=com.redhat.stacks.ubi9-python-312 \
	CNB_USER_ID=1001 \
	CNB_GROUP_ID=0 \
	PIP_NO_CACHE_DIR=off \
	PATH=/opt/app-root/bin/:$HOME/.local/bin/:$PATH

COPY --from=base-installer /mnt/rootfs/ /
COPY --from=base-installer /usr/share/buildinfo /


# Config-editor builds the javascript for the configtool.
FROM registry.access.redhat.com/ubi9/nodejs-22-minimal AS config-editor
WORKDIR /opt/app-root/src
COPY --chown=1001:0 config-tool/pkg/lib/editor/ ./
RUN set -ex \
	&& npm install --quiet --no-progress --ignore-engines \
	&& npm run --quiet build \
	&& rm -Rf .cache .npm* node_modules

# Build-python installs the requirements for the python code.
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest AS build-python

USER root
ENV PYTHONDONTWRITEBYTECODE=1

RUN set -ex \
	&& microdnf -y --setopt=tsflags=nodocs install \
	gcc-c++ \
	git \
	openldap-devel \
	python3.12 \
	python3.12-devel \
	libffi-devel \
	openssl-devel \
	diffutils \
	findutils \
	make \
	libjpeg-turbo \
	libjpeg-turbo-devel \
	libpq-devel \
	wget \
	rust-toolset \
	libxml2-devel \
	libxslt-devel \
	freetype-devel \
	&& microdnf -y clean all

WORKDIR /build
RUN mkdir -p /opt/app-root
RUN chown 1001:0 /opt/app-root
USER 1001

RUN python3.12 -m venv /opt/app-root
ENV PATH=/opt/app-root/bin/:$PATH

RUN python3 -m ensurepip --upgrade
COPY requirements.txt .
# Note that it installs into PYTHONUSERBASE because of the '--user'
# flag.

# Build configuration
# When cross-compiling the container, cargo uncontrollably consumes memory and
# gets killed by the OOM Killer when it fetches dependencies. The workaround is
# to use the git executable.
# See https://github.com/rust-lang/cargo/issues/10583 for details.
ENV GRPC_PYTHON_BUILD_SYSTEM_OPENSSL=1 \
	CARGO_NET_GIT_FETCH_WITH_CLI=true

# GRPC support for IBM Power (ppc64le)
# In Future if wget is to be removed, then uncomment below lines for grpc installation on IBM Power
RUN ARCH=$(uname -m) && echo $ARCH && \
	if [ "$ARCH" = "ppc64le" ]; then \
	GRPC_LATEST=$(grep "grpcio" requirements.txt | cut -d "=" -f 3) && \
	wget https://github.com/IBM/oss-ecosystem-grpc/releases/download/${GRPC_LATEST}/grpcio-${GRPC_LATEST}-cp312-cp312-linux_ppc64le.whl \
	-O /tmp/grpcio-${GRPC_LATEST}-cp312-cp312-linux_ppc64le.whl && \
	python3 -m pip install --no-cache-dir /tmp/grpcio-${GRPC_LATEST}-cp312-cp312-linux_ppc64le.whl; \
	fi

RUN set -ex \
	&& python3 -m pip install --no-cache-dir --progress-bar off \
	$(grep -e '^pip=' -e '^wheel=' -e '^setuptools=' ./requirements.txt) \
	&& python3 -m pip install --no-cache-dir --progress-bar off --requirement requirements.txt

RUN set -ex \
	&& rm -f /opt/app-root/bin/pip* \
	&& rm -rf /opt/app-root/lib/python3.12/site-packages/pip*

# Fix certifi permissions (explicitly against the purpose and use of certifi)
RUN set -ex \
	&& for dir in $(find "/opt/app-root/lib/python3.12/site-packages" -type d -name certifi); do \
	chgrp -R 0 "$dir" && chmod -R g=u "$dir"; \
	done

# Build-static downloads the static javascript.
FROM registry.access.redhat.com/ubi9/nodejs-22-minimal AS build-static
ARG BUILD_ANGULAR=true
WORKDIR /opt/app-root/src
# This below line is a workaround because in UBI 9, the OpenSSL version does not support MD4 anymore which is required by the combination of webpack and terser-webpack-plugin.
ENV NODE_OPTIONS=--openssl-legacy-provider
COPY --chown=1001:0 package.json package-lock.json  ./
RUN npm clean-install
COPY --chown=1001:0 static/  ./static/
COPY --chown=1001:0 *.json *.js  ./
RUN if [ "$BUILD_ANGULAR" = "true" ]; then npm run --quiet build; fi

# Build React UI
FROM registry.access.redhat.com/ubi9/nodejs-22-minimal:latest AS build-ui
WORKDIR /opt/app-root
COPY --chown=1001:0 web/package.json web/package-lock.json  ./
RUN CYPRESS_INSTALL_BINARY=0 npm clean-install
COPY --chown=1001:0 web .
RUN npm run --quiet build

# Pushgateway grabs pushgateway.
FROM registry.access.redhat.com/ubi9/ubi-minimal:latest AS pushgateway
ENV OS=linux
ARG PUSHGATEWAY_VERSION=1.11.2

RUN set -ex \
	&& microdnf update -y \
	&& microdnf -y --setopt=tsflags=nodocs install tar gzip \
	&& ARCH=$(uname -m) && echo $ARCH \
	&& if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; elif [ "$ARCH" = "aarch64" ]; then ARCH="arm64"; fi \
	&& TARBALL="pushgateway-${PUSHGATEWAY_VERSION}.${OS}-${ARCH}.tar.gz" \
	&& URL="https://github.com/prometheus/pushgateway/releases/download/v${PUSHGATEWAY_VERSION}/${TARBALL}" \
	&& (curl -sSL ${URL} | tar xz "pushgateway-${PUSHGATEWAY_VERSION}.${OS}-${ARCH}/pushgateway" \
	|| tar -xzf /cachi2/output/deps/generic/${TARBALL} "pushgateway-${PUSHGATEWAY_VERSION}.${OS}-${ARCH}/pushgateway") \
	&& install "pushgateway-${PUSHGATEWAY_VERSION}.${OS}-${ARCH}/pushgateway" /usr/local/bin/pushgateway

# Config-tool builds the go binary in the configtool.
FROM registry.access.redhat.com/ubi9/go-toolset AS config-tool
WORKDIR /opt/app-root/src
COPY config-tool/ ./
COPY --from=config-editor /opt/app-root/src/static/build  /opt/app-root/src/pkg/lib/editor/static/build
RUN GOPATH=/opt/app-root/src/go go install -tags=fips ./cmd/config-tool

# Build-skopeo compiles skopeo from source.
FROM registry.access.redhat.com/ubi9/go-toolset AS build-skopeo
USER root
WORKDIR /opt/app-root/src
RUN set -ex \
	&& dnf -y --setopt=tsflags=nodocs install git make pkg-config gpgme gpgme-devel libassuan-devel libgpg-error-devel openssl-devel \
	&& dnf -y clean all
RUN git clone https://github.com/containers/skopeo.git
WORKDIR /opt/app-root/src/skopeo
RUN make bin/skopeo

FROM registry.access.redhat.com/ubi9/ubi-minimal AS build-quaydir
WORKDIR /quaydir
COPY --from=config-editor /opt/app-root/src /quaydir/config_app
COPY --from=build-static /opt/app-root/src/static /quaydir/static
COPY --from=build-ui /opt/app-root/dist /quaydir/static/patternfly

# Copy in source and update local copy of AWS IP Ranges.
# This is a bad place to do the curl, but there's no good place to do
# it except to have it checked in.
COPY --chown=0:0 . .
RUN set -ex \
	&& chmod -R g=u ./conf \
	&& (curl -fsSL https://ip-ranges.amazonaws.com/ip-ranges.json -o util/ipresolver/aws-ip-ranges.json 2>/dev/null \
	|| cp /cachi2/output/deps/generic/aws-ip-ranges.json util/ipresolver/aws-ip-ranges.json)

# Final is the end container, where all the work from the other
# containers are copied in.
FROM base AS final
LABEL maintainer="quay-devel@redhat.com"

ENV QUAYDIR=/quay-registry \
	QUAYCONF=/quay-registry/conf \
	QUAYRUN=/quay-registry/conf \
	QUAYPATH=$QUAYDIR \
	PYTHONPATH=$QUAYPATH \
	PATH=/opt/app-root/bin/:$PATH

# All of these chgrp+chmod commands are an Openshift-ism.
#
# Openshift runs a container as a random UID and GID 0, so anything
# that's in the base image and needs to be modified at runtime needs
# to make sure it's group-writable.
RUN set -ex \
	&& setperms() { for d in "$@"; do chgrp -R 0 "$d" && chmod -R g=u "$d" && ls -ld "$d"; done; } \
	&& newdir() { for d in "$@"; do mkdir -m 775 "$d" && ls -ld "$d"; done; } \
	# Allow TLS certs to be created and installed as non-root user.
	# See also update-ca-trust(8).
	&& setperms /etc/pki/ca-trust/extracted /etc/pki/ca-trust/source/anchors \
	# Allow for nginx to run unprivledged.
	&& setperms /etc/nginx \
	&& ln -sf /dev/stdout /var/log/nginx/access.log \
	&& ln -sf /dev/stdout /var/log/nginx/error.log \
	# The code doesn't agree on where the configuration lives, so create a symlink.
	&& ln -s $QUAYCONF /conf \
	# Make a grip of runtime directories.
	&& newdir /certificates "$QUAYDIR" "$QUAYDIR/conf" "$QUAYDIR/conf/stack" /datastorage \
	# Another Openshift-ism: it doesn't bother picking a uid that means
	# anything to the OS inside the container, so the process needs
	# permissions to modify the user database.
	# Harden /etc/passwd – no group write.
	&& chown root:root /etc/passwd \
	&& chmod 0644 /etc/passwd \
	&& chown -R 1001:0 /etc/pki/ /etc/ssl/ /quay-registry \
	&& chmod ug+wx -R /etc/pki/ /etc/ssl/


WORKDIR $QUAYDIR
# Ordered from least changing to most changing.
COPY --from=pushgateway /usr/local/bin/pushgateway /usr/local/bin/pushgateway
COPY --from=build-python --chown=1001:0 /opt/app-root/ /opt/app-root/
COPY --from=config-tool /opt/app-root/src/go/bin/config-tool /bin
COPY --from=build-skopeo /opt/app-root/src/skopeo/bin/skopeo /usr/bin/skopeo
COPY --from=build-quaydir /quaydir $QUAYDIR

EXPOSE 8080 8443 7443 9091 55443
# Don't expose /var/log as a volume, because we just configured it
# correctly above.
# It's probably unwise to mount /tmp as a volume but if someone must,
# make sure it's mode 1777 like /tmp should be.
VOLUME ["/datastorage", "/tmp", "/conf/stack"]
# In non-Openshift environments, drop privilege.
USER 1001
ENTRYPOINT ["dumb-init", "--", "/quay-registry/quay-entrypoint.sh"]
CMD ["registry"]
