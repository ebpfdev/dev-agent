FROM golang:1.19

WORKDIR /build

# Downloading dependencies
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copying source files
COPY cmd cmd
COPY pkg pkg

# Building the binary
RUN GOOS=linux go build -a -o dev-agent cmd/dev-agent/main.go

# Building runtime image
FROM ubuntu:22.04

LABEL org.opencontainers.image.source=https://github.com/ebpfdev/dev-agent

WORKDIR /app
COPY --from=0 /build/dev-agent ./

CMD ["/app/dev-agent"]

