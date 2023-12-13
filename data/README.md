# Data collected

Name of file corresponds as follows: `YYYY_MM_DD_<client>_client_<server>_server_bm<bm>.csv`.
- YYYY is the year it was collected
- MM is the month it was collected
- DD is the day it was collected
- client is the client benchmarked
- server is the server the client talked to
- bm is the value `BENCH_MULTIPLIER` was set to

Newer data collects individual times now, have similar format:
`YYYY_MM_DD_<client>_client_<server>_server_p<p>.csv`. The only difference
being `p`, the number of points collected. Data collected is the time for a
handshake to complete, its units is in seconds.
