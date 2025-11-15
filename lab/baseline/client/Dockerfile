FROM alpine:3.19

RUN apk add --no-cache curl iproute2 bash

COPY health_check.sh /scripts/health_check.sh
COPY clientctl.sh /usr/local/bin/clientctl
COPY resolve.conf /etc/resolv.conf
RUN chmod +x /scripts/health_check.sh

WORKDIR /scripts
