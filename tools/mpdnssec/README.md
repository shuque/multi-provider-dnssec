# DNSSEC Multi-Provider API prototype

```
docker-compose build
docker-compose up --scale provider=3 --scale manager=1
```

```
./dig_all.sh +dnssec example.test. DNSKEY
```
