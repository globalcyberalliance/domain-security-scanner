FROM golang:1.26.0-alpine3.23 AS build

RUN apk add git make \
 && apk cache clean

WORKDIR /src

# Cache Go modules separately so this layer is reused until go.mod/go.sum change.
COPY go.mod go.sum ./
RUN go mod download

COPY . /src

# Stamp the binary with the release tag (VERSION build-arg). Left unset by default; an
# empty value makes `make prod` fall back to the version baked into cmd/dss/main.go, so
# local image builds are never shipped with an empty --version.
ARG VERSION
RUN make prod VERSION=$VERSION

FROM scratch

COPY --from=build /src/bin/dss /usr/bin/dss
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

WORKDIR /app

EXPOSE 8080

ENTRYPOINT ["dss"]

CMD ["serve", "api"]
