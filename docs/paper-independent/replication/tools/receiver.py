#!/usr/bin/env python3
"""S1 复现 receiver v0.1 —— AF_PACKET 绑 s1_rx，解析 wire record 并分类。
用法: sudo python3 receiver.py <ifname=s1_rx> <duration_s=25> <out=receiver.jsonl>
判定（见 SOURCES.md/01 文档）:
  conflict    = ingress_gen != egress_gen 且 semantic == d_lo^d_hi^I(ig)^E(eg)（receiver-corroborated）
  consistent  = ingress_gen == egress_gen 且 semantic 与之一致
  magic 缺失  = egress 未执行的帧（不计入 wire 判定，单独计数）
"""
import socket, sys, struct, json, time, signal

IF   = sys.argv[1] if len(sys.argv) > 1 else "s1_rx"
DUR  = float(sys.argv[2]) if len(sys.argv) > 2 else 25.0
OUT  = sys.argv[3] if len(sys.argv) > 3 else "receiver.jsonl"

CAPS_LEN, WIRE_LEN = 36, 72
OFF_PL   = 14 + 20 + 8            # eth + ip + udp
OFF_WIRE = OFF_PL + CAPS_LEN
NEED     = OFF_WIRE + WIRE_LEN
MAGIC    = 0x53315731
M        = 0xffffffff
SALT = {0: (0xa11a0a01, 0xa33a0a03), 1: (0xb22b0b02, 0xb44b0b04)}

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
s.bind((IF, socket.htons(3)))   # sockaddr_ll: (ifname, proto 网络序)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32 * 1024 * 1024)
s.settimeout(1.0)

running = True
def stop(*_):
    global running
    running = False
signal.signal(signal.SIGINT, stop)
signal.signal(signal.SIGTERM, stop)

seen = set()
rows = []
cnt = {"recv_total": 0, "recv_unique": 0, "dup": 0, "no_magic": 0,
       "conflict": 0, "consistent": 0, "mismatch": 0, "binding_err": 0}

t0 = time.time()
while running and time.time() - t0 < DUR:
    try:
        pkt = s.recv(65535)
    except socket.timeout:
        continue
    except OSError:
        break
    cnt["recv_total"] += 1
    if len(pkt) < NEED:
        continue
    pl = pkt[OFF_PL:OFF_PL + 172]
    if len(pl) < 172:
        continue
    cap = pl[:CAPSULE_LEN]
    w   = pl[CAPSULE_LEN:CAPSULE_LEN + WIRE_LEN]
    f16 = struct.unpack("<16I", w)
    magic, nonce, seq, tid, d_lo, d_hi, req_gen, ig, ib, eg, mid, si, se, sem, psig, act = f16
    if magic != MAGIC:
        cnt["no_magic"] += 1
        continue
    if (nonce, seq) in seen:
        cnt["dup"] += 1
        continue
    seen.add((nonce, seq))
    cnt["recv_unique"] += 1
    Ei, Ee = SALT.get(ig, (0, 0))[0], SALT.get(eg, (0, 0))[1]
    expected_retained = (d_lo ^ d_hi ^ Ei ^ Ee) & M
    cls = "mismatch"
    if ig != eg and sem == expected_retained:
        cls = "conflict"; cnt["conflict"] += 1
    elif ig == eg and sem == expected_retained:
        cls = "consistent"; cnt["consistent"] += 1
    req = struct.unpack_from("<I", cap, 28)[0]   # capsule.reserved[1] = requested_gen
    binding_err = 1 if req != ig else 0
    cnt["binding_err"] += binding_err
    rows.append({"nonce": nonce, "seq": seq, "req_gen": req, "ig": ig, "ib": ib,
                 "eg": eg, "mid": mid, "sem": sem, "psig": psig,
                 "binding_err": binding_err, "cls": cls})

with open(OUT, "w") as f:
    for r in rows:
        f.write(json.dumps(r) + "\n")
print(json.dumps(cnt), flush=True)
