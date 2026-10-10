# syntax=docker/dockerfile:1

FROM golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc AS build

ARG TARGETOS
ARG TARGETARCH

RUN mkdir /app
WORKDIR /app
COPY . /app/
RUN apk --no-cache add git=2.52.0-r0 make=4.4.1-r3 && \
    make build-docker-release GOOS=${TARGETOS} GOARCH=${TARGETARCH}

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS runner

ARG TARGETOS
ARG TARGETARCH

COPY --from=build /app/okta-logs-collector /usr/bin/okta-logs-collector

ENTRYPOINT ["/usr/bin/okta-logs-collector"]
