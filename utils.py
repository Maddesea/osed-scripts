"""
utils.py - Utility functions for exploit development

Provides common utilities for building ROP chains, managing connections,
and validating payloads for bad characters.
"""
import socket
from struct import pack
from typing import List, Union


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
