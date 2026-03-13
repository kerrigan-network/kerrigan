# syntax = devthefuture/dockerfile-x

FROM ./ci/ci.Dockerfile

# The inherited Dockerfile switches to non-privileged context and we've
# just started configuring this image, give us root access
USER root

# Make development environment more standalone, allow running Kerrigan Qt
RUN set -ex; \
    apt-get update && apt-get install ${APT_ARGS} \
    apt-cacher-ng \
    gdb \
    gpg \
    libxcb-icccm4 \
    libxcb-image0 \
    libxcb-keysyms1 \
    libxcb-randr0 \
    libxcb-render-util0 \
    libxcb-shape0 \
    libxcb-sync1 \
    libxcb-xfixes0 \
    libxcb-xinerama0 \
    libxcb-xkb1 \
    libxkbcommon-x11-0 \
    lsb-release \
    nano \
    openssh-client \
    screen \
    sudo \
    zsh \
    && \
    rm -rf /var/lib/apt/lists/*

# Discourage root access, this is an interactive instance
#
# Sometimes these commands are run repetitively _after_ the non-sudo
# user was introduced and therefore these commands would fail
# To mitigate the build halting, you can add "|| true" so that it
# unconditionally returns 0
#
RUN groupadd docker && \
    usermod -aG sudo kerrigan && \
    echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers; \
    mkdir -p /home/kerrigan/.config/gdb; \
    echo "add-auto-load-safe-path /usr/lib/llvm-${LLVM_VERSION}/lib" | tee /home/kerrigan/.config/gdb/gdbinit; \
    chown ${USER_ID}:${GROUP_ID} -R /home/kerrigan

# Disable noninteractive mode
ENV DEBIAN_FRONTEND="dialog"

# Expose Kerrigan P2P and RPC ports for main network and test networks
EXPOSE 7120 7121 17120 17121

# We're done, switch back to non-privileged user
USER kerrigan
