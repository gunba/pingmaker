# Pingmaker

Packet speed modifier for Aion 2. Intercepts inbound game packets and modifies attack speed values in real time.

Works with **ExitLag**, **GearUp**, and other gaming proxies/VPNs — captures both direct and loopback traffic.

## Requirements

- **Windows 10/11** (uses WinDivert kernel driver)
- **Run as Administrator** (required for packet capture)

## Quick Start

```bash
# Run from source (as Administrator)
python pingmaker.py
```

The GUI will launch. Click **Start** to begin capturing and modifying packets. The tool auto-detects game server ports.

### Pre-built Release

Download `Pingmaker.exe` from [Releases](../../releases) — no Python needed, just run as Administrator.

## How It Works

1. **Port detection** — Scans active TCP connections for Aion 2 game server ports
2. **Packet capture** — Uses WinDivert to intercept inbound game packets
3. **Speed modification** — Finds attack speed varint fields and replaces them with your target value
4. **Re-injection** — Sends modified packets back into the network stack

## License

[MIT](LICENSE)
