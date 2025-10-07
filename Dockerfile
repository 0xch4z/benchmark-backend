FROM golang:1.24-bullseye AS base

RUN adduser \
  --disabled-password \
  --gecos "" \
  --home "/nonexistent" \
  --shell "/sbin/nologin" \
  --no-create-home \
  --uid 65532 \
  small-user

WORKDIR $GOPATH/src/benchmark-backend/

COPY go.mod go.mod
COPY go.sum go.sum
COPY main.go main.go

RUN go mod download
RUN go mod verify

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
	-trimpath \
	-buildvcs=false \
	-ldflags="-s -w" \
	-o /bin/benchmark-backend .

FROM scratch

COPY --from=base /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=base /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=base /etc/passwd /etc/passwd
COPY --from=base /etc/group /etc/group

COPY --from=base /bin/benchmark-backend /bin/benchmark-backend

USER small-user:small-user

ENTRYPOINT ["/bin/benchmark-backend"]
