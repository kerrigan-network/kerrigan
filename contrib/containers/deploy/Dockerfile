FROM phusion/baseimage:jammy-1.0.4
LABEL maintainer="Kerrigan Developers <dev@kerrigan.network>"
LABEL description="Dockerised Kerrigan, built from CI"

ARG USER_ID
ARG GROUP_ID

ENV HOME="/home/kerrigan"

# add user with specified (or default) user/group ids
ENV USER_ID="${USER_ID:-1000}"
ENV GROUP_ID="${GROUP_ID:-1000}"
RUN groupadd -g ${GROUP_ID} kerrigan && \
    useradd -u ${USER_ID} -g kerrigan -s /bin/bash -m -d /home/kerrigan kerrigan && \
    mkdir /home/kerrigan/.kerrigan && \
    chown ${USER_ID}:${GROUP_ID} -R /home/kerrigan

COPY bin/* /usr/local/bin/

RUN chmod a+x /usr/local/bin/*

USER kerrigan

VOLUME ["/home/kerrigan"]

EXPOSE 7120 7121 17120 17121

WORKDIR /home/kerrigan
