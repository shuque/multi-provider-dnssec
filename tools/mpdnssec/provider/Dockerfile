FROM alpine:latest as builder
WORKDIR /root
COPY main.go /root/
RUN apk add --no-cache go git musl-dev
RUN \
	go get github.com/miekg/dns && \
	go get github.com/go-kit/kit/log && \
	go build -o provider main.go

FROM alpine:latest
WORKDIR /root
COPY knot.conf sign.sh update.sh entrypoint.sh unsigned.db /root/
COPY --from=builder /root/provider /root/
RUN apk add --no-cache knot bind-tools
ENTRYPOINT /root/entrypoint.sh
