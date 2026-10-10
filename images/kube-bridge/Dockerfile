FROM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/kube-bridge ./cmd/kube-bridge

FROM scratch
COPY --from=build /out/kube-bridge /kube-bridge
ENTRYPOINT ["/kube-bridge"]
