# syntax=docker/dockerfile:1

FROM golang:1.22.3-alpine3.20 AS build

ARG TARGETOS
ARG TARGETARCH

RUN mkdir /app
WORKDIR /app
COPY . /app/
RUN apk --no-cache add git=2.45.2-r0 make=4.4.1-r2 && \
    make build-docker-release GOOS=${TARGETOS} GOARCH=${TARGETARCH}

FROM alpine:3.20 AS runner

ARG TARGETOS
ARG TARGETARCH

COPY --from=build /app/okta-logs-collector /usr/bin/okta-logs-collector

ENTRYPOINT ["/usr/bin/okta-logs-collector"]
