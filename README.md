# cproxy-cli

A client line inferface to show datapath of cproxy, both frontend and backends.

```
usage: ./cproxycli tcp/udp frontend/backend frontend_ip/backend_ip:port
example: ./cproxycli frontend udp 172.17.0.2:53
example: ./cproxycli backend tcp 10.8.164.116:8080
```

Results:

```
# ./cproxycli frontend tcp 172.17.220.0:334
L4 frontend address tcp 172.17.220.0:334
--> backend address: tcp 10.8.107.247:3344
--> backend address: tcp 10.8.111.86:3344
--> backend address: tcp 10.8.118.154:3344
--> backend address: tcp 10.8.125.67:3344
--> backend address: tcp 10.8.128.235:3344
--> backend address: tcp 10.8.158.94:3344
--> backend address: tcp 10.8.177.148:3344
--> backend address: tcp 10.8.182.130:3344
--> backend address: tcp 10.8.189.227:3344
--> backend address: tcp 10.8.4.220:3344

./cproxycli backend tcp 10.8.158.94:3344
L4 address 10.8.158.94:3344 has backend id 19
<-- backend id 19 is redirected from frontend 172.17.220.0:334

```
