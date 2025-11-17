FROM golang:1.25.3-alpine3.22 AS build

RUN apk add git make \
 && apk cache clean

WORKDIR /src

# Install setup dependencies (e.g. betteralign)
COPY Makefile ./
RUN make setup

# Cache Go modules and local vendored dependencies needed for replacements
COPY go.mod go.sum ./
RUN go mod download

COPY . /src

RUN make

FROM scratch

COPY --from=build /src/bin/dss /usr/bin/dss
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

WORKDIR /app

EXPOSE 8080

ENTRYPOINT ["dss"]

CMD ["serve", "api"]