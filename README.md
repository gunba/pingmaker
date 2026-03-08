# Pingmaker

Latency compensation for Aion 2. Modifies inbound server response packets to adjust combat speed values, removing the artificial delay that ping adds between skill uses.

Compatible with **ExitLag**, **GearUp**, and other gaming proxies/VPNs.

## How It Works

![How Pingmaker Works](pingmaker_diagram.svg)

When you use a skill, the server responds with a combat speed value that determines how long your client locks you out. The problem is your ping gets added on top — so a 100ms ping player waits 100ms longer between every skill than a 0ms player, even though the server doesn't care.

Pingmaker intercepts the response and increases the combat speed, shortening the client lockout to compensate. The server still validates all timings independently — you can never act faster than it allows. Players below ~50ms ping see no difference due to tick rate.

## Quick Start

Download `Pingmaker.exe` from [Releases](https://github.com/gunba/pingmaker/releases) and run as Administrator.

From source: `python pingmaker.py` (requires Windows 10/11, admin).

## Usage

The combat speed % maps to the same in-game stat. You can increase it (globally or per skill) until there is no improvement. 

For Skills with non-mobile flag (i.e. can't move while casting), increasing the combat speed beyond what is necessary will cause rubberbanding. 

**Varint cap:** Characters at ≤164% combat speed (usually sub-3k GS, no scroll) are capped at 164% due to 2-byte encoding (the packet does not have space for a larger number). Use the **Break Packet** checkbox on no-cooldown skills to bypass this — don't use it on skills with cooldowns, as it breaks cooldown tracking.

## Building

See [BUILD.md](BUILD.md).

## License

[MIT](LICENSE)
