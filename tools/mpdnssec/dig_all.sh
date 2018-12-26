#!/bin/sh

for port in `docker-compose ps -q provider | xargs docker inspect --format '{{ index .NetworkSettings "Ports" "53/udp" 0 "HostPort" }}'`; do
	dig @127.0.0.1 -p "$port" $@
done
