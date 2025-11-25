# OSED Scripts - Comprehensive Usage Guide

This guide provides detailed instructions for using all tools in the OSED scripts toolkit.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
3. [Unified CLI (osed)](#unified-cli-osed)
4. [Standalone Scripts](#standalone-scripts)
   - [egghunter.py](#egghunterpy)
   - [pattern.py](#patternpy)
   - [find-gadgets.py](#find-gadgetspy)
   - [utils.py](#utilspy)
   - [exploit-template.py](#exploit-templatepy)
5. [WinDbg Scripts](#windbg-scripts)
   - [find-ppr.py](#find-pprpy)
   - [find-bad-chars.py](#find-bad-charspy)
   - [search.py](#searchpy)
6. [PowerShell Scripts](#powershell-scripts)
   - [attach-process.ps1](#attach-processps1)
   - [install-mona.ps1](#install-monaps1)
7. [Shell Scripts](#shell-scripts)
   - [install-mona.sh](#install-monash)
8. [Workflow Examples](#workflow-examples)
9. [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# Install dependencies
pip3 install keystone-engine rich ropper capstone

# Use the unified CLI
./osed info                              # Show all available commands
./osed egghunter -t w00t                 # Generate egghunter
./osed pattern create 1000               # Create cyclic pattern
./osed pattern find 0x41414141           # Find offset
./osed gadgets -f vuln.exe -b 00 0a 0d   # Find ROP gadgets

# Or use individual scripts directly
./egghunter.py -t w00t -b 00 0a 0d
./pattern.py create 1000
./find-gadgets.py -f vuln.exe
```

---

## Installation

### Prerequisites

- Python 3.9 or higher
- pip (Python package manager)

### Install Python Dependencies

```bash
# Core dependencies
pip3 install keystone-engine rich ropper capstone

# Optional: numpy (for shellcoder.py)
pip3 install numpy
```

### Clone the Repository

```bash
git clone https://github.com/epi052/osed-scripts.git
cd osed-scripts
```

### Make Scripts Executable

```bash
chmod +x osed egghunter.py pattern.py find-gadgets.py
```

### Add to PATH (Optional)

```bash
# Add to your ~/.bashrc or ~/.zshrc
export PATH="$PATH:/path/to/osed-scripts"
```

---

## Unified CLI (osed)

The `osed` command provides a single entry point for all tools.

### Basic Usage

```bash
# Show help and available commands
./osed
./osed info
./osed --help

# Show version
./osed version
./osed -V
```

### Commands

| Command | Description |
|---------|-------------|
| `egghunter` | Generate egghunter shellcode |
| `pattern` | Cyclic pattern generator/finder |
| `gadgets` | Find and categorize ROP gadgets |
| `info` | Display tool information |
| `version` | Show version info |

### Examples

```bash
# Egghunter with custom tag and bad chars
./osed egghunter -t w00t -b 00 0a 0d -f c -o egghunter.c

# Create 2000-byte pattern
./osed pattern create 2000

# Find offset of hex value
./osed pattern find 0x41386141

# Find gadgets with custom base address
./osed gadgets -f libspp.dll:0x10000000 -b 00 0a 0d
```

---

## Standalone Scripts

### egghunter.py

Generate egghunter shellcode for staged payload delivery.

#### Egghunter Variants

| Variant | Size | Description |
|---------|------|-------------|
| NtAccessCheckAndAuditAlarm | 35 bytes | Default, smallest |
| SEH-based | 69 bytes | More compatible |

#### Usage

```bash
./egghunter.py [OPTIONS]
```

#### Options

| Option | Description |
|--------|-------------|
| `-t, --tag TAG` | 4-character search tag (default: c0d3) |
| `-b, --bad-chars` | Space-separated bad characters |
| `-s, --seh` | Use SEH-based egghunter |
| `-f, --format` | Output format: python, c, raw, hex, escaped |
| `-o, --output FILE` | Save to file |
| `-v, --verbose` | Show assembly with bytes |
| `-n, --varname NAME` | Variable name (default: egghunter) |

#### Examples

```bash
# Default egghunter (NtAccess, 35 bytes)
./egghunter.py
# Output:
# [+] egghunter created!
# [=]   len: 35 bytes
# [=]   tag: c0d3c0d3
# egghunter = b"\x66\x81\xca\xff\x0f..."

# Custom tag
./egghunter.py -t w00t

# SEH-based with bad char check
./egghunter.py --seh -b 00 0a 0d

# C format output to file
./egghunter.py -t hack -f c -o egghunter.h

# Verbose mode (shows assembly)
./egghunter.py -v
```

#### Using the Egghunter

```python
# In your exploit
egg = b"w00tw00t"  # Tag (repeated twice)
egghunter = b"\x66\x81\xca\xff\x0f..."

# Place egghunter in accessible memory
# Place egg + shellcode somewhere in memory
# The egghunter will search for the egg and jump to shellcode
payload = egg + shellcode
```

---

### pattern.py

Generate and find offsets in cyclic patterns (de Bruijn sequences).

#### Usage

```bash
./pattern.py create <length> [OPTIONS]
./pattern.py find <sequence> [OPTIONS]
```

#### Create Command

Generate a cyclic pattern.

```bash
# Create 1000-byte pattern
./pattern.py create 1000

# Save to file
./pattern.py create 2000 -o pattern.txt

# Use custom charset
./pattern.py create 500 -c "ABCD"
```

#### Find Command

Find offset of a sequence in the pattern.

```bash
# Find hex address (little-endian)
./pattern.py find 0x41386141
# Output:
# [+] Offset: 1028
# [=] Hex:    0x00000404

# Find string sequence
./pattern.py find Aa0A

# Find without 0x prefix
./pattern.py find 41414141
```

#### Workflow

1. Generate pattern: `./pattern.py create 2000 -o pattern.txt`
2. Send pattern to vulnerable application
3. Application crashes, note EIP value (e.g., `0x41386141`)
4. Find offset: `./pattern.py find 0x41386141`
5. Use offset to place shellcode at exact location

---

### find-gadgets.py

Find and categorize ROP gadgets from binary files.

#### Features

- Uses both **ropper** and **rp++** for comprehensive coverage
- Categorizes gadgets by type
- Filters bad characters
- JSON output support
- Custom base addresses

#### Usage

```bash
./find-gadgets.py -f <files> [OPTIONS]
```

#### Options

| Option | Description |
|--------|-------------|
| `-f, --files FILES` | Binary files (required) |
| `-b, --bad-chars` | Bad characters to filter |
| `-a, --arch` | Architecture: x86, x86_64 (default: x86) |
| `-o, --output FILE` | Output file (default: found-gadgets.txt) |
| `-c, --color` | Colorize output |
| `-s, --skip-rp` | Skip rp++ integration |
| `-j, --json` | JSON output |
| `--json-output FILE` | JSON output file |

#### Examples

```bash
# Basic gadget search
./find-gadgets.py -f vuln.exe

# Multiple files with custom base address
./find-gadgets.py -f libspp.dll:0x10000000 libsync.dll

# Filter bad characters
./find-gadgets.py -f vuln.dll -b 00 0a 0d 20

# JSON output
./find-gadgets.py -f vuln.exe -j --json-output gadgets.json

# 64-bit binary
./find-gadgets.py -f vuln64.exe -a x86_64
```

#### Gadget Categories

| Category | Description | Example |
|----------|-------------|---------|
| write-what-where | Memory writes | `mov [eax], ecx; ret` |
| pointer-deref | Memory reads | `mov eax, [ebx]; ret` |
| swap-register | Register moves | `xchg eax, ecx; ret` |
| increment | Increment | `inc eax; ret` |
| decrement | Decrement | `dec eax; ret` |
| add | Addition | `add eax, ecx; ret` |
| subtract | Subtraction | `sub eax, ecx; ret` |
| negate | Negation | `neg eax; ret` |
| xor | XOR operation | `xor eax, eax; ret` |
| push | Push to stack | `push eax; ret` |
| pop | Pop from stack | `pop eax; ret` |
| pushad | Push all registers | `pushad; ret` |
| zeroize | Zero a register | `xor eax, eax; ret` |
| eip-to-esp | Stack pivot | `jmp esp` |

#### Output Files

- `found-gadgets.txt` - All gadgets (uncategorized)
- `found-gadgets.txt.clean` - Categorized gadgets

---

### utils.py

Utility library for exploit development.

#### RopChain Class

Build ROP chains with ease.

```python
from utils import RopChain, p32, u32, sanity_check

# Create ROP chain with base address
rop = RopChain(base=0x10000000)

# Add gadget offsets (automatically adds base)
rop += 0x1234      # Becomes 0x10001234
rop += 0x5678      # Becomes 0x10005678

# Add raw bytes
rop += b"\x90" * 4

# Add absolute values (no base added)
rop.append_raw(0x41414141)

# Get the chain
payload = rop.chain
print(f"ROP chain: {len(rop)} bytes")
```

#### Helper Functions

```python
from utils import p32, p64, u32, u64, cyclic, cyclic_find, sanity_check, get_connection

# Pack/unpack addresses
addr = p32(0x41414141)    # b'\x41\x41\x41\x41'
addr = p64(0x414141414141)
val = u32(b'\x41\x41\x41\x41')  # 0x41414141

# Cyclic patterns
pattern = cyclic(1000)
offset = cyclic_find(0x41414141)

# Check for bad characters
bad_chars = [0x00, 0x0a, 0x0d]
sanity_check(payload, bad_chars)  # Raises SystemExit if found

# Get connection with retry
sock = get_connection("192.168.1.100", 9999)
```

---

### exploit-template.py

Template for building exploits with ROP chains.

#### Features

- Pre-configured ROP chain templates
- VirtualProtect, VirtualAlloc, WriteProcessMemory
- SEH overwrite template
- Bad character checking
- Connection management

#### Usage

1. Copy the template to your working directory
2. Fill in offsets and gadgets
3. Add shellcode
4. Run and test

```bash
cp exploit-template.py my_exploit.py
# Edit my_exploit.py with your gadgets and shellcode
python3 my_exploit.py
```

#### ROP Chain Templates

```python
# VirtualProtect - Change memory protections
# BOOL VirtualProtect(lpAddress, dwSize, flNewProtect, lpflOldProtect)
skeleton = RopChain()
skeleton += 0x41414141  # VirtualProtect address
skeleton += 0x42424242  # Return address (shellcode)
skeleton += 0x43434343  # lpAddress (ESP)
skeleton += 0x44444444  # dwSize (0x300)
skeleton += 0x45454545  # flNewProtect (0x40 = RWX)
skeleton += 0x46464646  # lpflOldProtect (writable addr)

# VirtualAlloc - Allocate executable memory
# LPVOID VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)

# WriteProcessMemory - Write to code cave
# BOOL WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, *lpNumberOfBytesWritten)
```

---

## WinDbg Scripts

These scripts require WinDbg with the pykd extension.

### Setup

```
.load pykd
!py C:\path\to\script.py [args]
```

Or add scripts to `C:\Python37\Scripts` for simpler invocation:
```
!py script.py [args]
```

---

### find-ppr.py

Find `pop r32; pop r32; ret` gadgets for SEH exploits.

#### Usage

```
!py find-ppr.py -m <modules> [OPTIONS]
```

#### Options

| Option | Description |
|--------|-------------|
| `-m, --modules` | Module names to search (required) |
| `-b, --bad` | Bad characters to filter |
| `-s, --showbc` | Show addresses with bad chars |

#### Example

```
0:000> !py find-ppr.py -m libspp libsync -b 00 0A 0D

[+] searching libspp for pop r32; pop r32; ret
[+] BADCHARS: \x00\x0A\x0D
[OK] libspp::0x101582b0: pop eax; pop ebx; ret ; \xB0\x82\x15\x10
[OK] libspp::0x1001bc5a: pop ebx; pop ecx; ret ; \x5A\xBC\x01\x10
...
[+] libspp: Found 316 usable gadgets!

---- STATS ----
>> BADCHARS: \x00\x0A\x0D
>> Usable Gadgets Found: 316
>> Module Gadget Counts
   - libspp: 316
```

---

### find-bad-chars.py

Identify bad characters in memory.

#### Modes

1. **--address**: Compare memory with expected bytes
2. **--generate**: Generate Python byte string

#### Usage

```
!py find-bad-chars.py (-a ADDRESS | -g) [OPTIONS]
```

#### Options

| Option | Description |
|--------|-------------|
| `-a, --address` | Memory address to compare |
| `-g, --generate` | Generate byte string |
| `-s, --start` | Start byte (default: 0x00) |
| `-e, --end` | End byte (default: 0xFF) |
| `-b, --bad` | Known bad characters |

#### Examples

```
# Compare memory at ESP+1
!py find-bad-chars.py --address esp+1 --bad 00 --start 01 --end 7f

0185ff55  01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10
          01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10
0185ff65  11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F 20
          11 12 13 14 15 16 17 18 19 1A 1B 1C -- 1E 1F 20
#                                            ^^ 0x1D is bad!

# Generate byte string excluding known bad chars
!py find-bad-chars.py --generate --bad 00 0a 0d 1d --start 01

[+] characters as a byte string
chars  = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0B\x0C\x0E\x0F\x10'
chars += b'\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1E\x1F'
...
```

---

### search.py

Search memory for patterns.

#### Usage

```
!py search.py [-t TYPE] <pattern>
```

#### Types

| Type | Description |
|------|-------------|
| `byte` | Hex byte search (default) |
| `ascii` | ASCII string search |
| `unicode` | Unicode string search |

#### Examples

```
# Search for ASCII string
!py search.py -t ascii "password"

# Search for hex bytes
!py search.py -t byte "90 90 90 90"

# Search for unicode
!py search.py -t unicode "admin"
```

---

## PowerShell Scripts

### attach-process.ps1

Attach WinDbg to a process with automatic service restart.

#### Parameters

| Parameter | Description |
|-----------|-------------|
| `-service-name` | Service to restart (optional) |
| `-path` | Executable path to launch (optional) |
| `-process-name` | Process to attach to (required) |
| `-commands` | WinDbg commands to run at startup |

#### Examples

```powershell
# Attach to service-based application
.\attach-process.ps1 -service-name fastbackserver -process-name fastbackserver

# With startup commands
.\attach-process.ps1 -service-name fastbackserver -process-name fastbackserver `
    -commands '.load pykd; bp fastbackserver!recvfrom; g'

# Launch executable and attach
.\attach-process.ps1 -path C:\app\vuln.exe -process-name vuln

# Automated debugging loop
while ($true) {
    .\attach-process.ps1 -process-name vuln `
        -commands '.load pykd; bp 0x401234; g; !exchain; g; p; p; p'
}
```

---

### install-mona.ps1

Install mona.py on Windows lab VM.

Run from an Administrator PowerShell after using `install-mona.sh`:

```powershell
powershell -c "cat \\tsclient\mona-share\install-mona.ps1 | powershell -"
```

---

## Shell Scripts

### install-mona.sh

Download and set up mona.py components.

#### Usage

```bash
./install-mona.sh <lab-vm-ip>
```

#### What it Does

1. Downloads mona.py, windbglib.py, pykd
2. Downloads Python 2.7 MSI and vcredist
3. Creates RDP share directory
4. Opens RDP connection to lab VM
5. Displays installation instructions

#### Example

```bash
./install-mona.sh 192.168.45.123

# Once RDP opens, run in Admin PowerShell:
# powershell -c "cat \\tsclient\mona-share\install-mona.ps1 | powershell -"
```

---

## Workflow Examples

### Standard Buffer Overflow

```bash
# 1. Generate cyclic pattern
./osed pattern create 2000 -o pattern.txt

# 2. Send pattern, note crash EIP
# EIP = 0x41386141

# 3. Find offset
./osed pattern find 0x41386141
# Offset: 1028

# 4. Generate egghunter (if needed for staged payload)
./osed egghunter -t w00t -b 00 0a 0d

# 5. Find ROP gadgets
./osed gadgets -f vuln.dll -b 00 0a 0d

# 6. Build exploit using exploit-template.py
```

### SEH Exploit Development

```bash
# 1. Find SEH offset using pattern
./osed pattern create 5000 -o pattern.txt
# Send pattern, check SEH chain in debugger
./osed pattern find 0x????????

# 2. Find pop-pop-ret gadgets (in WinDbg)
# !py find-ppr.py -m vuln_module -b 00 0a 0d

# 3. Build SEH exploit using template
cp exploit-template.py seh_exploit.py
# Fill in get_seh_overwrite() function
```

### Bad Character Identification

```bash
# 1. Generate test string
# In WinDbg: !py find-bad-chars.py --generate --start 01

# 2. Send test string in exploit

# 3. Compare in memory
# In WinDbg: !py find-bad-chars.py --address esp+1 --start 01

# 4. Note bad characters, regenerate excluding them
# !py find-bad-chars.py --generate --bad 00 0a 0d 1d --start 01
```

---

## Troubleshooting

### Common Issues

#### "keystone-engine not found"

```bash
pip3 install keystone-engine
```

#### "ropper not found"

```bash
pip3 install ropper
```

#### "rp++ download failed"

The script will automatically download rp++. If it fails:
- Check internet connectivity
- Use `--skip-rp` flag to skip rp++ integration
- Download manually from https://github.com/0vercl0k/rp/releases

#### WinDbg scripts not working

1. Ensure pykd is loaded: `.load pykd`
2. Check Python 2.7 is installed (for mona.py compatibility)
3. Verify script path is correct

#### Bad characters in generated shellcode

Use msfvenom to encode:
```bash
cat shellcode.bin | msfvenom --platform windows -a x86 \
    -e x86/shikata_ga_nai -b "\x00\x0a\x0d" -f python
```

### Getting Help

- Check the [README.md](README.md) for quick start
- Open an issue on GitHub for bugs
- See [ENHANCEMENTS.md](ENHANCEMENTS.md) for recent changes

---

## Quick Reference Card

```
OSED Tools Quick Reference
==========================

Unified CLI:
  osed egghunter -t TAG -b BADCHARS -f FORMAT
  osed pattern create LENGTH
  osed pattern find SEQUENCE
  osed gadgets -f FILES -b BADCHARS

Egghunter:
  ./egghunter.py -t w00t -b 00 0a 0d -s --seh -f c

Pattern:
  ./pattern.py create 1000
  ./pattern.py find 0x41414141

Gadgets:
  ./find-gadgets.py -f lib.dll:0x10000000 -b 00 0a -j

WinDbg (with pykd):
  !py find-ppr.py -m module -b 00 0a 0d
  !py find-bad-chars.py -a esp+1 -b 00
  !py find-bad-chars.py -g --bad 00 0a
  !py search.py -t ascii "string"

PowerShell:
  .\attach-process.ps1 -service-name svc -process-name proc

Shell:
  ./install-mona.sh 192.168.x.x
```
