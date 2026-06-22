# syntax=docker/dockerfile:1

FROM golang:1.26.3-alpine3.23@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS build

ARG TARGETOS
ARG TARGETARCH

RUN mkdir /app
WORKDIR /app
COPY . /app/
RUN apk --no-cache add git=2.52.0-r0 make=4.4.1-r3 && \
    make build-docker-release GOOS=${TARGETOS} GOARCH=${TARGETARCH}

FROM alpine:3.23@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40 AS runner

ARG TARGETOS
ARG TARGETARCH

COPY --from=build /app/okta-logs-collector /usr/bin/okta-logs-collector

ENTRYPOINT ["/usr/bin/okta-logs-collector"]
