#!/usr/bin/python3
"""
pattern.py - Cyclic pattern generator for finding buffer overflow offsets

This tool generates unique cyclic patterns (de Bruijn sequences) for identifying
offsets in buffer overflows. Compatible with Metasploit's pattern_create.

Usage:
    Generate pattern: ./pattern.py create 1000
    Find offset:      ./pattern.py find 0x61616161
    Find offset:      ./pattern.py find aaaa
"""
import sys
import argparse
import struct
from struct import pack, unpack
import string


def cyclic_pattern(length: int, charset: str = None) -> bytes:
    """
    Generate a cyclic de Bruijn sequence.

    Args:
        length: Length of pattern to generate
        charset: Custom character set (default: lowercase alphabet)

    Returns:
        Cyclic pattern bytes
    """
    if charset is None:
        charset = string.ascii_lowercase

    # Use simple repeating pattern similar to Metasploit
    # Pattern: Aa0Aa1Aa2Aa3...
    pattern = b''
    upper = string.ascii_uppercase
    lower = string.ascii_lowercase
    digits = string.digits

    for i in range(len(upper)):
        for j in range(len(lower)):
            for k in range(len(digits)):
                if len(pattern) >= length:
                    return pattern[:length]
                pattern += upper[i:i+1].encode() + lower[j:j+1].encode() + digits[k:k+1].encode()

    # If we need more, repeat
    while len(pattern) < length:
        pattern += pattern

    return pattern[:length]


def find_offset(subseq: str, charset: str = None) -> int:
    """
    Find offset of a subsequence in the cyclic pattern.

    Args:
        subseq: Sequence to find (hex or string)
        charset: Custom character set used

    Returns:
        Offset or -1 if not found
    """
    # Try to parse as hex first
    try:
        if subseq.startswith('0x') or subseq.startswith('0X'):
            # Hex address (e.g., 0x61616161)
            addr = int(subseq, 16)
            subseq_bytes = pack('<I', addr)
        elif all(c in '0123456789abcdefABCDEF' for c in subseq) and len(subseq) == 8:
            # Hex without 0x prefix
            addr = int(subseq, 16)
            subseq_bytes = pack('<I', addr)
        else:
            # String sequence (e.g., "Aa0A")
            subseq_bytes = subseq.encode()
    except (ValueError, struct.error):
        subseq_bytes = subseq.encode()

    # Generate a large pattern
    pattern = cyclic_pattern(20000, charset)
    offset = pattern.find(subseq_bytes)

    return offset


def main():
    """Main function to handle pattern operations."""
    parser = argparse.ArgumentParser(
        description="Cyclic pattern generator for finding buffer overflow offsets",
        epilog="Examples:\n"
               "  %(prog)s create 1000       # Generate 1000-byte pattern\n"
               "  %(prog)s find 0x61616161   # Find offset of hex value\n"
               "  %(prog)s find Aa0A         # Find offset of string\n",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='command', help='Command to execute')

    # Create pattern command
    create_parser = subparsers.add_parser('create', help='Generate cyclic pattern')
    create_parser.add_argument(
        'length',
        type=int,
        help='Length of pattern to generate'
    )
    create_parser.add_argument(
        '-c', '--charset',
        help='Custom character set to use',
        default=None
    )
    create_parser.add_argument(
        '-o', '--output',
        help='Output file (default: stdout)',
        default=None
    )

    # Find offset command
    find_parser = subparsers.add_parser('find', help='Find offset in pattern')
    find_parser.add_argument(
        'sequence',
        help='Sequence to find (hex address or string, e.g., 0x61616161 or Aa0A)'
    )
    find_parser.add_argument(
        '-c', '--charset',
        help='Custom character set used in pattern',
        default=None
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'create':
        # Generate pattern
        if args.length < 1:
            print("[!] Length must be positive", file=sys.stderr)
            sys.exit(1)

        if args.length > 20000:
            print("[!] Warning: Very large pattern requested", file=sys.stderr)

        pattern = cyclic_pattern(args.length, args.charset)

        if args.output:
            try:
                with open(args.output, 'wb') as f:
                    f.write(pattern)
                print(f"[+] Pattern written to {args.output}")
            except IOError as e:
                print(f"[!] Failed to write to file: {e}", file=sys.stderr)
                sys.exit(1)
        else:
            # Print to stdout
            try:
                sys.stdout.buffer.write(pattern)
            except AttributeError:
                # Python 2 compatibility
                sys.stdout.write(pattern.decode('latin-1'))

    elif args.command == 'find':
        # Find offset
        offset = find_offset(args.sequence, args.charset)

        if offset == -1:
            print(f"[!] Sequence '{args.sequence}' not found in pattern", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"[+] Offset: {offset}")
            print(f"[=] Hex:    0x{offset:08x}")

            # Also show in different formats
            try:
                if args.sequence.startswith('0x'):
                    addr = int(args.sequence, 16)
                    bytes_le = pack('<I', addr)
                    print(f"[=] Bytes:  {' '.join(f'{b:02x}' for b in bytes_le)}")
            except (ValueError, struct.error):
                pass


if __name__ == '__main__':
    main()
