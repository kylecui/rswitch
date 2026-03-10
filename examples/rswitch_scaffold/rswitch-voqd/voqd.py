#!/usr/bin/env python3
import time, queue, threading, yaml, pathlib, os
from collections import defaultdict

VOQ = defaultdict(lambda: [queue.Queue(maxsize=8192) for _ in range(4)])
DEFICIT = defaultdict(lambda: [0,0,0,0])
QUANTUM = [1500,3000,6000,9000]
RATE = defaultdict(lambda: [10_000_000]*4)

def load_cfg(path="config.yaml"):
    if not pathlib.Path(path).exists():
        return
    cfg = yaml.safe_load(open(path))
    for port, pdata in cfg.get("ports", {}).items():
        p = int(port)
        for sp, q in pdata.get("prio", {}).items():
            pr = int(sp)
            QUANTUM[pr] = q.get("quantum", QUANTUM[pr])
            # Simplified: apply globally for demo
            # For per-port rate, you can maintain RATE[p][pr]
    print("[cfg] loaded.")

def ringbuf_consumer_demo():
    # Demo: synthesize metadata; replace with libbpf ringbuf consumer
    port=1
    while True:
        for pr in [3,0,0,0,2,1]:
            try:
                VOQ[port][pr].put_nowait({"eg_port":port,"prio":pr,"len":1500})
            except queue.Full:
                pass
        time.sleep(0.001)

def token_bucket_allow(port, prio, length):
    # TODO: implement per-Q token bucket
    return True

def drr_loop():
    while True:
        for port, qs in list(VOQ.items()):
            for pr in reversed(range(4)):
                DEFICIT[port][pr] += QUANTUM[pr]
                q = qs[pr]
                while DEFICIT[port][pr] > 0 and not q.empty():
                    pkt = q.get_nowait()
                    if not token_bucket_allow(port, pr, pkt["len"]):
                        break
                    # TODO: send via AF_XDP Tx
                    DEFICIT[port][pr] -= pkt["len"]
        time.sleep(0)

if __name__ == "__main__":
    load_cfg()
    threading.Thread(target=ringbuf_consumer_demo, daemon=True).start()
    drr_loop()
