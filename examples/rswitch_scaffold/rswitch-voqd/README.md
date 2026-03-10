# rswitch-voqd

User-space VOQ Daemon (skeleton) to consume metadata from `rswitch-xdp` ringbuf/AF_XDP,
apply **DRR/WFQ + TokenBucket** scheduling, and transmit via AF_XDP Tx or raw sockets.
This is a **minimal starter** you can extend.

## Files
- `voqd.py` — reference Python skeleton (queueing & DRR loop)
- `config.yaml` — per-port/prio config (quantum, rate)
- `requirements.txt` — Python deps

> For production or higher performance, reimplement in Go or C with AF_XDP.
