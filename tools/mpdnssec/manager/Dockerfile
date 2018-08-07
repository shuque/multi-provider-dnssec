FROM alpine:latest as builder
WORKDIR /root
COPY main.go /root/
RUN apk add --no-cache go git musl-dev
RUN \
	go get github.com/miekg/dns && \
	go get github.com/go-kit/kit/log && \
	go build -o manager main.go

FROM alpine:latest
WORKDIR /root
COPY --from=builder /root/manager /root/
ENTRYPOINT /root/manager
