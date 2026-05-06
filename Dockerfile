# syntax=docker/dockerfile:1

FROM golang:1.26.2-alpine3.23 AS build

ARG TARGETOS
ARG TARGETARCH

RUN mkdir /app
WORKDIR /app
COPY . /app/
RUN apk --no-cache add git=2.52.0-r0 make=4.4.1-r3 && \
    make build-docker-release GOOS=${TARGETOS} GOARCH=${TARGETARCH}

FROM alpine:3.23@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11 AS runner

ARG TARGETOS
ARG TARGETARCH

COPY --from=build /app/okta-logs-collector /usr/bin/okta-logs-collector

ENTRYPOINT ["/usr/bin/okta-logs-collector"]
