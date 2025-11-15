# VOQd Quick Reference

## Build
```bash
cd rswitch/ && make clean && make
```

## Run Modes

### SHADOW Mode (Safe Testing)
```bash
sudo ./build/rswitch-voqd -p 4 -m shadow -s -S 10
```
- ✅ No AF_XDP required
- ✅ Tests VOQ logic
- ✅ Zero risk to traffic

### ACTIVE Mode (Production)
```bash
sudo ./build/rswitch-voqd \
    -p 4 -m active -P 0x0F \
    -i ens33,ens34,ens35,ens36 \
    -s -S 10
```
- ⚠️ Requires AF_XDP support
- ⚠️ Requires interface names
- ✅ Full packet processing

## Quick Commands

### Configuration
```bash
# Set port rate limit (100 Mbps)
sudo ./build/rsvoqctl set-port-rate \
    --port 0 --rate 100000000 --burst 65536

# Set queue parameters
sudo ./build/rsvoqctl set-queue-params \
    --port 0 --prio 3 --quantum 2048 --max-depth 8192
```

### Monitoring
```bash
# Show statistics
sudo ./build/rsvoqctl show-stats

# Watch live stats
watch -n 2 "sudo ./build/rsvoqctl show-stats"
```

## Priority Mask

| Value | Priority | Use Case |
|-------|----------|----------|
| 0x01 | LOW | Best-effort |
| 0x02 | NORMAL | Standard |
| 0x04 | HIGH | Priority |
| 0x08 | CRITICAL | Time-sensitive |
| 0x0F | ALL | All priorities |

## Files

### Binaries
- `build/rswitch-voqd` (118K) - Main daemon
- `build/rsvoqctl` (29K) - Control tool

### Documentation
- `docs/VOQd_Usage_Guide.md` - User manual
- `docs/VOQd_DataPlane_Implementation.md` - Technical details
- `docs/VOQd_Integration_Summary.md` - This sprint summary

### Tools
- `tools/test_voqd.sh` - Automated test suite

## Troubleshooting

### AF_XDP not supported
```bash
# Use SHADOW mode instead
sudo ./build/rswitch-voqd -m shadow -s
```

### Interface not found
```bash
# List available interfaces
ip link show
# Use correct names in -i option
```

### Permission denied
```bash
# Must run as root
sudo ./build/rswitch-voqd ...
```

## Next Steps

1. Test in your environment
2. Configure rate limits
3. Monitor statistics
4. Tune for performance

See `docs/VOQd_Usage_Guide.md` for full documentation.
