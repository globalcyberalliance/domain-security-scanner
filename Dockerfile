FROM golang:1.23.1-alpine3.20 AS build

RUN apk add git make \
 && apk cache clean \
 && go install github.com/dkorunic/betteralign/cmd/betteralign@latest

COPY . /go/src/github.com/globalcyberalliance/domain-security-scanner/

WORKDIR /go/src/github.com/globalcyberalliance/domain-security-scanner/

RUN make

FROM scratch

COPY --from=build /go/src/github.com/globalcyberalliance/domain-security-scanner/bin/dss /dss
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENTRYPOINT [ "/dss" ]