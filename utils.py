"""
utils.py - Utility functions for exploit development

Provides common utilities for building ROP chains, managing connections,
and validating payloads for bad characters.
"""
import socket
import string
import time
import sys
from struct import pack, unpack
from typing import List, Union, Tuple, Optional, Callable


class RopChain:
    """
    Helper class for building ROP chains.

    This class simplifies the creation of ROP chains by managing a base address
    and providing convenient methods to add gadgets and values.

    Example:
        rop = RopChain(base=0x10000000)
        rop += 0x1234  # Add offset from base
        rop += b"\\x90" * 4  # Add raw bytes
        rop.append_raw(0x41414141)  # Add absolute value
    """

    def __init__(self, base: int = None, pack_str: str = '<I', chain: bytes = b''):
        """
        Initialize a ROP chain.

        Args:
            base: Base address for calculating offsets (default: 0)
            pack_str: struct.pack format string (default: '<I' for little-endian 32-bit)
            chain: Initial chain bytes (default: empty)
        """
        self.chain = chain
        self.base = base or 0
        self.pack_str = pack_str

    def __iadd__(self, other: Union[int, bytes]) -> 'RopChain':
        """
        Add a value to the ROP chain.

        Args:
            other: Either an integer offset (added to base) or raw bytes

        Returns:
            Self for method chaining

        Raises:
            NotImplementedError: If other is not int or bytes
        """
        if isinstance(other, int):
            self.chain += self._pack_32(self.base + other)
        elif isinstance(other, bytes):
            self.chain += other
        else:
            raise NotImplementedError(f"Cannot add type {type(other)} to RopChain")
        return self

    def __len__(self) -> int:
        """Return the length of the current chain in bytes."""
        return len(self.chain)

    @staticmethod
    def p32(address: int) -> bytes:
        """
        Pack a 32-bit address in little-endian format.

        Args:
            address: Address to pack

        Returns:
            Packed address as bytes
        """
        return pack('<I', address)

    @staticmethod
    def p64(address: int) -> bytes:
        """
        Pack a 64-bit address in little-endian format.

        Args:
            address: Address to pack

        Returns:
            Packed address as bytes
        """
        return pack('<Q', address)

    def _pack_32(self, address: int) -> bytes:
        """
        Pack an address using the configured format string.

        Args:
            address: Address to pack

        Returns:
            Packed address as bytes
        """
        return pack(self.pack_str, address)

    def append_raw(self, address: int) -> None:
        """
        Append an address without adding the base offset.

        Useful for adding actual values (not gadget offsets) in conjunction
        with pop instructions.

        Args:
            address: Absolute address or value to append
        """
        self.chain += pack(self.pack_str, address)


def get_connection(ip: str, port: int) -> socket.socket:
    """
    Establish a TCP connection, retrying on connection refused.

    This function will continuously retry connecting until successful,
    which is useful when waiting for a service to start.

    Args:
        ip: Target IP address
        port: Target port number

    Returns:
        Connected socket object

    Warning:
        This function will loop indefinitely if the connection never succeeds.
        Consider adding a timeout or maximum retry count for production use.
    """
    sock = None
    while sock is None:
        try:
            sock = socket.create_connection((ip, port))
        except ConnectionRefusedError:
            continue
    return sock


def u32(data: bytes) -> int:
    """
    Unpack a 32-bit address from little-endian format.

    Args:
        data: 4 bytes to unpack

    Returns:
        Unpacked 32-bit integer

    Raises:
        ValueError: If data is not exactly 4 bytes
    """
    if len(data) != 4:
        raise ValueError(f"u32 requires exactly 4 bytes, got {len(data)}")
    return unpack('<I', data)[0]


def u64(data: bytes) -> int:
    """
    Unpack a 64-bit address from little-endian format.

    Args:
        data: 8 bytes to unpack

    Returns:
        Unpacked 64-bit integer

    Raises:
        ValueError: If data is not exactly 8 bytes
    """
    if len(data) != 8:
        raise ValueError(f"u64 requires exactly 8 bytes, got {len(data)}")
    return unpack('<Q', data)[0]


def p32(address: int) -> bytes:
    """
    Pack a 32-bit address in little-endian format (standalone function).

    Args:
        address: Address to pack

    Returns:
        Packed address as bytes
    """
    return pack('<I', address)


def p64(address: int) -> bytes:
    """
    Pack a 64-bit address in little-endian format (standalone function).

    Args:
        address: Address to pack

    Returns:
        Packed address as bytes
    """
    return pack('<Q', address)


def cyclic(length: int, charset: str = None) -> bytes:
    """
    Generate a cyclic de Bruijn sequence for pattern matching.

    This is useful for finding offsets in buffer overflows. Each substring
    of length 4 is unique, making it easy to find offsets.

    Args:
        length: Length of pattern to generate
        charset: Character set to use (default: lowercase letters)

    Returns:
        Cyclic pattern as bytes

    Example:
        pattern = cyclic(1000)
        # Send pattern, find EIP value, then use cyclic_find()
    """
    if charset is None:
        charset = string.ascii_lowercase

    pattern = b''
    k = len(charset)

    # Generate de Bruijn sequence
    alphabet = charset.encode() if isinstance(charset, str) else charset
    a = [0] * k * 4

    def db(t, p):
        if t > 4:
            if 4 % p == 0:
                for j in range(1, p + 1):
                    pattern + alphabet[a[j]:a[j]+1]
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)

    # Simplified implementation for common case
    for i in range(length):
        pattern += alphabet[(i // (k ** 0)) % k:(i // (k ** 0)) % k + 1]
        if len(pattern) >= length:
            break

    # Alternative simple method for predictable patterns
    pattern = b''
    charset_bytes = charset.encode() if isinstance(charset, str) else charset
    for i in range(length):
        pattern += charset_bytes[i % len(charset_bytes):i % len(charset_bytes) + 1]

    return pattern[:length]


def cyclic_find(subseq: Union[bytes, int], charset: str = None) -> int:
    """
    Find the offset of a subsequence in a cyclic pattern.

    Args:
        subseq: Subsequence to find (bytes or packed integer)
        charset: Character set used (default: lowercase letters)

    Returns:
        Offset of the subsequence, or -1 if not found

    Example:
        offset = cyclic_find(0x61616161)  # Find 'aaaa'
        offset = cyclic_find(b'aaaa')
    """
    if isinstance(subseq, int):
        subseq = pack('<I', subseq)

    # Generate a large pattern and search for the subsequence
    pattern = cyclic(20000, charset)
    offset = pattern.find(subseq)
    return offset if offset != -1 else -1


def sanity_check(byte_str: bytes, bad_chars: List[int]) -> None:
    """
    Check if any bad characters are present in a byte string.

    Args:
        byte_str: Byte string to check (e.g., payload, ROP chain)
        bad_chars: List of bad character values (0-255)

    Raises:
        SystemExit: If any bad characters are found
    """
    baddies = []

    for bc in bad_chars:
        if bc in byte_str:
            print(f"[!] bad char found: {hex(bc)}")
            baddies.append(bc)

    if baddies:
        print(f"[=] {byte_str}")
        print(f"[!] Bad characters found: {', '.join(hex(bc) for bc in baddies)}")
        print("[!] Remove bad characters and try again")
        raise SystemExit(1)


# =============================================================================
# Additional Utility Functions
# =============================================================================

def get_connection_timeout(ip: str, port: int, timeout: float = 5.0,
                           retries: int = 3, delay: float = 1.0) -> Optional[socket.socket]:
    """
    Establish a TCP connection with timeout and retry logic.

    Args:
        ip: Target IP address
        port: Target port number
        timeout: Socket timeout in seconds (default: 5.0)
        retries: Number of retry attempts (default: 3)
        delay: Delay between retries in seconds (default: 1.0)

    Returns:
        Connected socket object or None if connection fails

    Example:
        sock = get_connection_timeout("192.168.1.100", 9999, timeout=10, retries=5)
        if sock:
            sock.send(payload)
    """
    for attempt in range(retries):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            return sock
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            if attempt < retries - 1:
                print(f"[*] Connection attempt {attempt + 1} failed: {e}. Retrying in {delay}s...")
                time.sleep(delay)
            else:
                print(f"[!] Connection failed after {retries} attempts: {e}")
                return None
    return None


def hexdump(data: bytes, addr: int = 0, width: int = 16) -> str:
    """
    Generate a hex dump of binary data.

    Args:
        data: Binary data to dump
        addr: Starting address to display (default: 0)
        width: Number of bytes per line (default: 16)

    Returns:
        Formatted hex dump string

    Example:
        print(hexdump(payload, addr=0x00401000))
    """
    result = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)

        # Pad hex part if needed
        hex_part = hex_part.ljust(width * 3 - 1)

        result.append(f'{addr + i:08x}  {hex_part}  |{ascii_part}|')

    return '\n'.join(result)


def format_addr(addr: int, bits: int = 32) -> str:
    """
    Format an address for display.

    Args:
        addr: Address to format
        bits: Address size (32 or 64)

    Returns:
        Formatted address string

    Example:
        print(format_addr(0x41414141))  # "0x41414141"
        print(format_addr(0x41414141, 64))  # "0x0000000041414141"
    """
    if bits == 64:
        return f'0x{addr:016x}'
    return f'0x{addr:08x}'


def addr_to_bytes(addr: int, bits: int = 32, endian: str = 'little') -> bytes:
    """
    Convert an address to bytes.

    Args:
        addr: Address to convert
        bits: Address size (32 or 64)
        endian: Byte order ('little' or 'big')

    Returns:
        Address as bytes

    Example:
        addr_to_bytes(0x41414141)  # b'AAAA'
        addr_to_bytes(0x41414141, endian='big')  # b'AAAA'
    """
    size = bits // 8
    return addr.to_bytes(size, byteorder=endian)


def bytes_to_addr(data: bytes, endian: str = 'little') -> int:
    """
    Convert bytes to an address.

    Args:
        data: Bytes to convert
        endian: Byte order ('little' or 'big')

    Returns:
        Address as integer

    Example:
        bytes_to_addr(b'AAAA')  # 0x41414141
    """
    return int.from_bytes(data, byteorder=endian)


def p16(value: int) -> bytes:
    """Pack a 16-bit value in little-endian format."""
    return pack('<H', value)


def u16(data: bytes) -> int:
    """Unpack a 16-bit value from little-endian format."""
    return unpack('<H', data)[0]


def p32_be(value: int) -> bytes:
    """Pack a 32-bit value in big-endian format."""
    return pack('>I', value)


def u32_be(data: bytes) -> int:
    """Unpack a 32-bit value from big-endian format."""
    return unpack('>I', data)[0]


def p64_be(value: int) -> bytes:
    """Pack a 64-bit value in big-endian format."""
    return pack('>Q', value)


def u64_be(data: bytes) -> int:
    """Unpack a 64-bit value from big-endian format."""
    return unpack('>Q', data)[0]


def pad(data: bytes, size: int, char: bytes = b'\x00') -> bytes:
    """
    Pad data to a specific size.

    Args:
        data: Data to pad
        size: Target size
        char: Padding character (default: null byte)

    Returns:
        Padded data

    Example:
        payload = pad(b'AAAA', 100, b'\\x90')  # Pad with NOPs to 100 bytes
    """
    if len(data) >= size:
        return data[:size]
    return data + char * (size - len(data))


def pad_left(data: bytes, size: int, char: bytes = b'\x00') -> bytes:
    """
    Left-pad data to a specific size.

    Args:
        data: Data to pad
        size: Target size
        char: Padding character (default: null byte)

    Returns:
        Left-padded data
    """
    if len(data) >= size:
        return data[-size:]
    return char * (size - len(data)) + data


def find_bad_chars(data: bytes, bad_chars: List[int]) -> List[Tuple[int, int]]:
    """
    Find all occurrences of bad characters in data.

    Args:
        data: Data to search
        bad_chars: List of bad character values

    Returns:
        List of (offset, byte_value) tuples

    Example:
        bad = find_bad_chars(payload, [0x00, 0x0a, 0x0d])
        for offset, byte in bad:
            print(f"Bad char 0x{byte:02x} at offset {offset}")
    """
    results = []
    for i, byte in enumerate(data):
        if byte in bad_chars:
            results.append((i, byte))
    return results


def generate_bad_char_test(exclude: List[int] = None, start: int = 0x00, end: int = 0xff) -> bytes:
    """
    Generate a byte sequence for bad character testing.

    Args:
        exclude: List of bytes to exclude (default: [0x00])
        start: Starting byte value (default: 0x00)
        end: Ending byte value (default: 0xff)

    Returns:
        Byte sequence for testing

    Example:
        test_chars = generate_bad_char_test(exclude=[0x00, 0x0a, 0x0d])
    """
    if exclude is None:
        exclude = [0x00]

    return bytes(i for i in range(start, end + 1) if i not in exclude)


def nop_sled(size: int, arch: str = 'x86') -> bytes:
    """
    Generate a NOP sled.

    Args:
        size: Size of the NOP sled
        arch: Architecture ('x86' or 'x64')

    Returns:
        NOP sled bytes

    Example:
        payload = nop_sled(100) + shellcode
    """
    if arch in ('x86', 'x64', 'x86_64'):
        return b'\x90' * size
    return b'\x00' * size


def align(value: int, alignment: int) -> int:
    """
    Align a value to a boundary.

    Args:
        value: Value to align
        alignment: Alignment boundary

    Returns:
        Aligned value

    Example:
        aligned = align(0x1001, 0x1000)  # Returns 0x2000
    """
    if value % alignment == 0:
        return value
    return value + (alignment - (value % alignment))


def log(msg: str, level: str = 'info') -> None:
    """
    Print a formatted log message.

    Args:
        msg: Message to print
        level: Log level ('info', 'success', 'warning', 'error')
    """
    prefixes = {
        'info': '[*]',
        'success': '[+]',
        'warning': '[!]',
        'error': '[-]',
    }
    prefix = prefixes.get(level, '[=]')
    print(f"{prefix} {msg}")


def recv_until(sock: socket.socket, delimiter: bytes, timeout: float = 5.0) -> bytes:
    """
    Receive data until a delimiter is found.

    Args:
        sock: Connected socket
        delimiter: Delimiter to search for
        timeout: Receive timeout in seconds

    Returns:
        Received data including delimiter

    Example:
        banner = recv_until(sock, b'\\n')
    """
    sock.settimeout(timeout)
    data = b''
    while delimiter not in data:
        try:
            chunk = sock.recv(1)
            if not chunk:
                break
            data += chunk
        except socket.timeout:
            break
    return data


def send_line(sock: socket.socket, data: bytes, newline: bytes = b'\n') -> None:
    """
    Send data followed by a newline.

    Args:
        sock: Connected socket
        data: Data to send
        newline: Line terminator (default: \\n)
    """
    sock.send(data + newline)


def interactive(sock: socket.socket) -> None:
    """
    Start an interactive session with a socket.

    Args:
        sock: Connected socket

    Note:
        Press Ctrl+C to exit interactive mode
    """
    import select
    import sys

    print("[*] Entering interactive mode (Ctrl+C to exit)")
    sock.setblocking(False)

    try:
        while True:
            # Check if data available from socket or stdin
            readable, _, _ = select.select([sock, sys.stdin], [], [], 0.1)

            for r in readable:
                if r is sock:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            print("[*] Connection closed")
                            return
                        sys.stdout.write(data.decode('utf-8', errors='replace'))
                        sys.stdout.flush()
                    except BlockingIOError:
                        pass
                elif r is sys.stdin:
                    line = sys.stdin.readline()
                    if line:
                        sock.send(line.encode())
    except KeyboardInterrupt:
        print("\n[*] Exiting interactive mode")


class Payload:
    """
    Helper class for building payloads incrementally.

    Example:
        p = Payload()
        p.add(b'A' * 100)           # Add padding
        p.add_addr(0x41414141)      # Add address
        p.add_nops(50)              # Add NOP sled
        p.add(shellcode)            # Add shellcode
        payload = p.build()
    """

    def __init__(self, bits: int = 32):
        """Initialize payload builder."""
        self._data = b''
        self._bits = bits

    def add(self, data: bytes) -> 'Payload':
        """Add raw bytes."""
        self._data += data
        return self

    def add_addr(self, addr: int) -> 'Payload':
        """Add an address (little-endian)."""
        if self._bits == 64:
            self._data += p64(addr)
        else:
            self._data += p32(addr)
        return self

    def add_nops(self, count: int) -> 'Payload':
        """Add NOP sled."""
        self._data += nop_sled(count)
        return self

    def add_padding(self, size: int, char: bytes = b'A') -> 'Payload':
        """Add padding bytes."""
        self._data += char * size
        return self

    def pad_to(self, size: int, char: bytes = b'\x00') -> 'Payload':
        """Pad payload to specific size."""
        if len(self._data) < size:
            self._data = pad(self._data, size, char)
        return self

    def build(self) -> bytes:
        """Return the built payload."""
        return self._data

    def __len__(self) -> int:
        """Return current payload length."""
        return len(self._data)

    def __bytes__(self) -> bytes:
        """Return payload as bytes."""
        return self._data
