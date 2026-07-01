#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

CONTAINER_NAME="otp-build-debian"
IMAGE_ALIAS="images:debian/12"
HOST_SHARE_DIR="$(pwd)/shared"
OFFLINE_DIR="$HOST_SHARE_DIR/offline"
CONTAINER_SHARE_DIR="/shared"

echo "Creating offline directory at $OFFLINE_DIR..."
mkdir -p "$OFFLINE_DIR"

PACKAGES="build-essential cmake git wget autoconf m4 libncurses-dev libwxgtk3.2-dev libgl1-mesa-dev libglu1-mesa-dev libpng-dev libssh-dev unixodbc-dev xsltproc fop libxml2-utils default-jdk pkg-config"

echo "-----------------------------------------------------------------"
echo "Setting up an isolated APT environment on the host..."
echo "This ensures we download exactly Debian 12 (bookworm) packages"
echo "and ALL their dependencies, regardless of your host's OS version."
echo "-----------------------------------------------------------------"

MOCK_APT="$OFFLINE_DIR/mock-apt"

echo "Cleaning up any old .deb files from previous runs to prevent version conflicts..."
rm -f "$OFFLINE_DIR/"*.deb

mkdir -p "$MOCK_APT/etc/apt/trusted.gpg.d" \
         "$MOCK_APT/etc/apt/preferences.d" \
         "$MOCK_APT/var/lib/apt/lists/partial" \
         "$MOCK_APT/var/cache/apt/archives/partial" \
         "$MOCK_APT/var/lib/dpkg"

touch "$MOCK_APT/var/lib/dpkg/status"
# Use [trusted=yes] to bypass GPG checks since we lack the host's Debian keyring in this isolated mock
echo "deb [trusted=yes] http://deb.debian.org/debian bookworm main" > "$MOCK_APT/etc/apt/sources.list"
echo "deb [trusted=yes] http://deb.debian.org/debian bookworm-updates main" >> "$MOCK_APT/etc/apt/sources.list"
echo "deb [trusted=yes] http://security.debian.org/debian-security bookworm-security main" >> "$MOCK_APT/etc/apt/sources.list"

echo "Updating isolated APT lists for Debian 12..."
# Use APT::Sandbox::User=root to prevent apt from dropping privileges to _apt, avoiding home directory permission issues
sudo apt-get -o Dir="$MOCK_APT" -o Dir::State::status="$MOCK_APT/var/lib/dpkg/status" -o APT::Sandbox::User=root update

echo "Downloading all required Debian 12 packages..."
sudo apt-get -o Dir="$MOCK_APT" -o Dir::State::status="$MOCK_APT/var/lib/dpkg/status" -o APT::Sandbox::User=root install --download-only -y $PACKAGES

# Move downloaded deb files up to the offline directory
mv "$MOCK_APT/var/cache/apt/archives/"*.deb "$OFFLINE_DIR/" 2>/dev/null || true
# Clean up mock apt
sudo rm -rf "$MOCK_APT"

echo "Downloading GmSSL source on the host..."
if [ ! -d "$OFFLINE_DIR/GmSSL" ]; then
    git clone https://github.com/guanzhi/GmSSL.git "$OFFLINE_DIR/GmSSL"
else
    echo "GmSSL source already exists in $OFFLINE_DIR/GmSSL"
fi

# Launch the Debian container
echo "Launching container $CONTAINER_NAME from $IMAGE_ALIAS..."
# If it exists, delete it first to start clean since it got polluted with host packages
if incus info "$CONTAINER_NAME" >/dev/null 2>&1; then
    echo "Removing broken container $CONTAINER_NAME..."
    incus delete -f "$CONTAINER_NAME"
fi
incus launch "$IMAGE_ALIAS" "$CONTAINER_NAME"

# Wait for the container to initialize
echo "Waiting for container to boot..."
sleep 5

# Mount the shared directory
echo "Mounting shared directory from host to container..."
incus config device add "$CONTAINER_NAME" shared_disk disk source="$HOST_SHARE_DIR" path="$CONTAINER_SHARE_DIR" shift=true

# Install packages offline inside the container
echo "Installing strictly Debian 12 packages offline inside the container..."
incus exec "$CONTAINER_NAME" -- bash -c "
    mkdir -p /tmp/debs && \
    cp $CONTAINER_SHARE_DIR/offline/*.deb /tmp/debs/ 2>/dev/null || true && \
    if ls /tmp/debs/*.deb 1> /dev/null 2>&1; then
        echo 'Installing .deb files using apt-get...'
        # dpkg -i first might fail on deps, but puts them in the database so apt-get install -f can fix it
        # Actually, apt-get install /tmp/debs/*.deb is the cleanest way
        apt-get install -y --no-install-recommends /tmp/debs/*.deb || \\
        (echo 'Fallback to dpkg...' && dpkg -i /tmp/debs/*.deb)
    else
        echo 'No .deb files found in $CONTAINER_SHARE_DIR/offline/'
    fi
"

# Build and Install GmSSL from source (offline)
echo "Compiling and installing GmSSL..."
incus exec "$CONTAINER_NAME" -- bash -c "
    if [ -d $CONTAINER_SHARE_DIR/offline/GmSSL ]; then
        cp -r $CONTAINER_SHARE_DIR/offline/GmSSL /tmp/GmSSL && \
        cd /tmp/GmSSL && \
        mkdir -p build && cd build && \
        cmake -DENABLE_SM2_AMD64=OFF .. && \
        make -j\$(nproc) && \
        make install && \
        ldconfig
    else
        echo 'GmSSL source not found in offline directory!'
    fi
"

echo "================================================================"
echo "Container '$CONTAINER_NAME' is successfully provisioned offline!"
echo "================================================================"
