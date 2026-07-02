#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

CONTAINER_NAME="otp-build-debian"
CONTAINER_SHARE_DIR="/shared"

echo "Starting OTP compilation inside container '$CONTAINER_NAME'..."

# Execute the compilation commands inside the container
incus exec "$CONTAINER_NAME" -- bash -c "
    if [ ! -d '$CONTAINER_SHARE_DIR/otp' ]; then
        echo 'Error: OTP source directory not found at $CONTAINER_SHARE_DIR/otp inside the container.'
        echo 'Please ensure you have cloned or extracted the OTP source code into the shared/otp directory on your host.'
        exit 1
    fi

    cd $CONTAINER_SHARE_DIR/otp
    export ERL_TOP=\$(pwd)
    
    echo '--- Running autoconf ---'
    ./otp_build autoconf
    
    echo '--- Running configure ---'
    # Using --with-ssl to ensure it picks up the crypto libraries (including the installed GmSSL)
    ./configure --with-ssl
    
    echo '--- Running make ---'
    make -j\$(nproc)
    
    echo '--- Compilation complete ---'
"

echo "Done! OTP has been successfully compiled inside the container."
