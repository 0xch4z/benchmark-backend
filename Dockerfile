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

RUN go mod download
RUN go mod verify

COPY main.go main.go

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
	-trimpath \
	-buildvcs=false \
	-ldflags="-s -w" \
	-o /bin/benchmark-backend .

FROM gcr.io/distroless/base-debian12:nonroot

COPY --from=base /bin/benchmark-backend /bin/benchmark-backend

USER nonroot

ENTRYPOINT ["/bin/benchmark-backend"]
