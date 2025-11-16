#!/usr/bin/env python3
"""
find-gadgets.py - Find and categorize useful ROP gadgets

This script uses both ropper and rp++ to find comprehensive ROP gadgets
from binary files, categorizing them by type for easier exploit development.
"""
import re
import sys
import json
import shutil
import argparse
import tempfile
import subprocess
from pathlib import Path
from typing import List, Tuple, Set, Dict, Any
import multiprocessing
import platform

og_print = print
from rich import print
from rich.tree import Tree
from rich.markup import escape
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from ropper import RopperService

console = Console()


class Gadgetizer:
    """Main class for finding and categorizing ROP gadgets."""

    def __init__(self, files: List[str], badbytes: List[str], output: str, arch: str, color: bool):
        """
        Initialize the Gadgetizer.

        Args:
            files: List of binary files to analyze (can include base addresses)
            badbytes: List of bad characters to filter out
            output: Output file path for gadgets
            arch: Target architecture (x86 or x86_64)
            color: Whether to use colored output
        """
        self.arch = arch
        self.color = color
        self.files = files
        self.output = output
        self.badbytes = "".join(badbytes)  # ropper's badbytes option has to be an instance of str
        self.ropper_svc = self.get_ropper_service()
        self.addresses: Set[str] = set()

    def get_ropper_service(self) -> RopperService:
        """
        Initialize and configure the RopperService.

        Returns:
            Configured RopperService instance

        Raises:
            SystemExit: If files cannot be loaded or analyzed
        """
        options = {
            "color": self.color,
            "badbytes": self.badbytes,
            "type": "rop",
        }

        rs = RopperService(options)

        for file in self.files:
            try:
                if ":" in file:
                    file, base = file.split(":")
                    if not Path(file).exists():
                        print(f"[bright_red][!][/bright_red] File not found: {file}", file=sys.stderr)
                        raise SystemExit(1)
                    rs.addFile(file, arch=self.arch)
                    rs.clearCache()
                    rs.setImageBaseFor(name=file, imagebase=int(base, 16))
                else:
                    if not Path(file).exists():
                        print(f"[bright_red][!][/bright_red] File not found: {file}", file=sys.stderr)
                        raise SystemExit(1)
                    rs.addFile(file, arch=self.arch)
                    rs.clearCache()

                rs.loadGadgetsFor(file)
            except Exception as e:
                print(f"[bright_red][!][/bright_red] Failed to load file {file}: {e}", file=sys.stderr)
                raise SystemExit(1)

        return rs

    def get_gadgets(self, search_str: str, quality: int = 1, strict: bool = False) -> List[Tuple]:
        """
        Search for gadgets matching a pattern.

        Args:
            search_str: Regex pattern to search for
            quality: Maximum number of instructions per gadget
            strict: If True, don't retry with lower quality

        Returns:
            List of (file, gadget) tuples
        """
        try:
            gadgets = [
                (f, g)
                for f, g in self.ropper_svc.search(search=search_str, quality=quality)
            ]

            if not gadgets and quality < self.ropper_svc.options.inst_count and not strict:
                # attempt highest quality gadget, continue requesting with lower quality until something is returned
                return self.get_gadgets(search_str, quality=quality + 1)

            return gadgets
        except Exception as e:
            print(f"[bright_yellow][!][/bright_yellow] Error searching for '{search_str}': {e}")
            return []

    def _search_gadget(self, title, search_strs):
        title = f"[bright_yellow]{title}[/bright_yellow] gadgets"
        tree = Tree(title)
        gadget_filter = re.compile(r'ret 0x[0-9a-fA-F]{3,};')  # filter out rets larger than 255

        for search_str in search_strs:
            for file, gadget in self.get_gadgets(search_str):
                if gadget_filter.search(gadget.simpleString()):
                    # not sure how to filter large ret sizes within ropper's search functionality, so doing it here
                    continue
                tree.add(f"{escape(str(gadget)).replace(':', '  #', 1)} :: {file}")
                self.addresses.add(hex(gadget.address))

        return tree

    def add_gadgets_to_tree(self, tree):
        zeroize_strs = []
        reg_prefix = "e" if self.arch == "x86" else "r"

        eip_to_esp_strs = [
            f"jmp {reg_prefix}sp;",
            "leave;",
            f"mov {reg_prefix}sp, ???;",
            f"call {reg_prefix}sp;",
        ]

        tree.add(self._search_gadget("write-what-where", ["mov [???], ???;"]))
        tree.add(self._search_gadget("pointer deref", ["mov ???, [???];"]))
        tree.add(
            self._search_gadget(
                "swap register",
                ["mov ???, ???;", "xchg ???, ???;", "push ???; pop ???;"],
            )
        )
        tree.add(self._search_gadget("increment register", ["inc ???;"]))
        tree.add(self._search_gadget("decrement register", ["dec ???;"]))
        tree.add(self._search_gadget("add register", [f"add ???, {reg_prefix}??;"]))
        tree.add(
            self._search_gadget("subtract register", [f"sub ???, {reg_prefix}??;"])
        )
        tree.add(self._search_gadget("negate register", [f"neg {reg_prefix}??;"]))
        tree.add(self._search_gadget("xor register", [f"xor {reg_prefix}??, 0x????????"]))
        tree.add(self._search_gadget("push", [f"push {reg_prefix}??;"]))
        tree.add(self._search_gadget("pushad", [f"pushad;"]))
        tree.add(self._search_gadget("pop", [f"pop {reg_prefix}??;"]))
        tree.add(
            self._search_gadget(
                "push-pop", [f"push {reg_prefix}??;.*pop {reg_prefix}??;*"]
            )
        )

        for reg in [
            f"{reg_prefix}ax",
            f"{reg_prefix}bx",
            f"{reg_prefix}cx",
            f"{reg_prefix}dx",
            f"{reg_prefix}si",
            f"{reg_prefix}di",
        ]:
            zeroize_strs.append(f"xor {reg}, {reg};")
            zeroize_strs.append(f"sub {reg}, {reg};")
            zeroize_strs.append(f"lea [{reg}], 0;")
            zeroize_strs.append(f"mov {reg}, 0;")
            zeroize_strs.append(f"and {reg}, 0;")
            eip_to_esp_strs.append(f"xchg {reg_prefix}sp, {reg}; jmp {reg};")
            eip_to_esp_strs.append(f"xchg {reg_prefix}sp, {reg}; call {reg};")

        tree.add(self._search_gadget("zeroize", zeroize_strs))
        tree.add(self._search_gadget("eip to esp", eip_to_esp_strs))

    def save(self):
        self.ropper_svc.options.color = False

        with open(self.output, "w") as f:
            for file in self.files:
                if ":" in file:
                    file = file.split(":")[0]

                for gadget in self.ropper_svc.getFileFor(name=file).gadgets:
                    f.write(f"{gadget}\n")

    def to_json(self) -> Dict[str, Any]:
        """
        Convert gadgets to JSON format.

        Returns:
            Dictionary containing categorized gadgets
        """
        result = {
            "metadata": {
                "arch": self.arch,
                "bad_bytes": self.badbytes,
                "files": [f.split(":")[0] if ":" in f else f for f in self.files]
            },
            "gadgets": {}
        }

        # Categorize gadgets
        reg_prefix = "e" if self.arch == "x86" else "r"

        categories = {
            "write-what-where": ["mov [???], ???;"],
            "pointer-deref": ["mov ???, [???];"],
            "swap-register": ["mov ???, ???;", "xchg ???, ???;", "push ???; pop ???;"],
            "increment": ["inc ???;"],
            "decrement": ["dec ???;"],
            "add": [f"add ???, {reg_prefix}??;"],
            "subtract": [f"sub ???, {reg_prefix}??;"],
            "negate": [f"neg {reg_prefix}??;"],
            "xor": [f"xor {reg_prefix}??, 0x????????"],
            "push": [f"push {reg_prefix}??;"],
            "pop": [f"pop {reg_prefix}??;"],
            "pushad": ["pushad;"],
            "eip-to-esp": [f"jmp {reg_prefix}sp;", "leave;", f"call {reg_prefix}sp;"]
        }

        for category, patterns in categories.items():
            result["gadgets"][category] = []
            for pattern in patterns:
                for file, gadget in self.get_gadgets(pattern):
                    result["gadgets"][category].append({
                        "address": hex(gadget.address),
                        "instructions": gadget.simpleString().split(": ")[1] if ": " in gadget.simpleString() else gadget.simpleString(),
                        "file": file
                    })

        return result


def add_missing_gadgets(ropper_addresses: Set[str], in_file: str, outfile: str, bad_bytes: List[str], base_address: str = None) -> None:
    """
    Use rp++ to find additional gadgets not found by ropper.

    For some reason rp++ finds significantly more gadgets than ropper alone.
    This function adds those missing gadgets to ropper's output.

    Args:
        ropper_addresses: Set of addresses already found by ropper
        in_file: Binary file to analyze
        outfile: Output file path
        bad_bytes: List of bad characters to filter
        base_address: Optional base address for the binary
    """
    fname = ''
    if platform.system() == 'Linux':
        fname = 'rp-lin-x64'
    elif platform.system() == "Darwin":
        fname = 'rp-osx-x64'
    else:
        print(f"[bright_yellow][!][/bright_yellow] rp++ not available for {platform.system()}, skipping")
        return

    rp = Path('~/.local/bin/' + fname).expanduser().resolve()

    if not rp.exists():
        print(f"[bright_yellow][*][/bright_yellow] rp++ not found, downloading...")
        try:
            rp.parent.mkdir(parents=True, exist_ok=True)

            wget = shutil.which('wget')
            if not wget:
                print(f"[bright_red][!][/bright_red] wget not found, please install it or add -s|--skip-rp to your command")
                return

            result = subprocess.run(
                f'{wget} https://github.com/0vercl0k/rp/releases/download/v2.0.2/{fname} -O {rp}'.split(),
                capture_output=True,
                timeout=60
            )
            if result.returncode != 0:
                print(f"[bright_red][!][/bright_red] Failed to download rp++: {result.stderr.decode()}")
                return

            rp.chmod(mode=0o755)
        except subprocess.TimeoutExpired:
            print(f"[bright_red][!][/bright_red] Download timed out")
            return
        except Exception as e:
            print(f"[bright_red][!][/bright_red] Failed to download rp++: {e}")
            return

    try:
        with tempfile.TemporaryFile(mode='w+', suffix='osed-rop') as tmp_file, open(outfile, 'a') as af:

            command = f'{rp} -r5 -f {in_file} --unique'

            if bad_bytes:
                bad_bytes_str = ''.join([f"\\x{byte}" for byte in bad_bytes])
                command += f' --bad-bytes={bad_bytes_str}'
            if base_address:
                command += f' --va={base_address}'

            print(f"[bright_green][+][/bright_green] running '{command}'")
            try:
                result = subprocess.run(command.split(), stdout=tmp_file, stderr=subprocess.PIPE, timeout=300)
                if result.returncode != 0 and result.stderr:
                    print(f"[bright_yellow][!][/bright_yellow] rp++ warning: {result.stderr.decode()}")
            except subprocess.TimeoutExpired:
                print(f"[bright_red][!][/bright_red] rp++ timed out after 5 minutes")
                return
            except Exception as e:
                print(f"[bright_red][!][/bright_red] Failed to run rp++: {e}")
                return

            tmp_file.seek(0)

            gadgets_added = 0
            for line in tmp_file.readlines():
                if not line.startswith('0x'):
                    continue

                rp_address = line.split(':')[0]

                if rp_address not in ropper_addresses:
                    truncated = line.rsplit(';', maxsplit=1)[0]
                    af.write(f'{truncated}\n')
                    gadgets_added += 1

            if gadgets_added > 0:
                print(f"[bright_green][+][/bright_green] Added {gadgets_added} additional gadgets from rp++")
    except IOError as e:
        print(f"[bright_red][!][/bright_red] File I/O error: {e}")
    except Exception as e:
        print(f"[bright_red][!][/bright_red] Unexpected error: {e}")


def clean_up_all_gadgets(outfile: str) -> None:
    """
    Normalize output from ropper and rp++.

    Both tools format their output slightly differently. This function
    normalizes spacing and formatting for consistency.

    Args:
        outfile: Path to the gadget output file
    """
    normal_spaces = re.compile(r'[ ]{2,}')
    normal_semicolon = re.compile(r'[ ]+?;')

    with tempfile.TemporaryFile(mode='w+', suffix='osed-rop') as tmp_file, open(outfile, 'r+') as f:
        for line in f.readlines():
            # rp++ adds a bunch of spaces around everything. normalize them for easier regex
            line = normal_spaces.sub(' ', line)

            # rp++ adds a bunch of spaces around semi-colons, ropper does not. normalize them for easier regex
            line = normal_semicolon.sub(';', line)

            # change "0x97753db7: add ..." to "0x97753db7  # add ..." for easy addition to source code
            line = line.replace(':', '  #', 1)

            tmp_file.write(line)

        tmp_file.seek(0)

        f.seek(0)
        f.write(tmp_file.read())
        # tmp_file became shorter than the original, need to remove the old contents that persist beyond
        # what was just written
        f.truncate()


def print_useful_regex(outfile: str, arch: str) -> None:
    """
    Print helpful regex patterns for searching the output file.

    Args:
        outfile: Path to the gadget output file
        arch: Target architecture
    """

    reg_prefix = "e" if arch == "x86" else "r"
    len_sort = "| awk '{ print length, $0 }' | sort -n -s -r | cut -d' ' -f2- | tail"
    any_reg = f'{reg_prefix}..'

    search_terms = list()
    search_terms.append(f'(jmp|call) {reg_prefix}sp;')
    search_terms.append(fr'mov {any_reg}, \[{any_reg}\];')
    search_terms.append(fr'mov \[{any_reg}\], {any_reg};')
    search_terms.append(fr'mov {any_reg}, {any_reg};')
    search_terms.append(fr'xchg {any_reg}, {any_reg};')
    search_terms.append(fr'push {any_reg};.*pop {any_reg};')
    search_terms.append(fr'inc {any_reg};')
    search_terms.append(fr'dec {any_reg};')
    search_terms.append(fr'neg {any_reg};')
    search_terms.append(fr'push {any_reg};')
    search_terms.append(fr'pop {any_reg};')
    search_terms.append('pushad;')
    search_terms.append(fr'and {any_reg}, ({any_reg}|0x.+?);')
    search_terms.append(fr'xor {any_reg}, ({any_reg}|0x.+?);')
    search_terms.append(fr'add {any_reg}, ({any_reg}|0x.+?);')
    search_terms.append(fr'sub {any_reg}, ({any_reg}|0x.+?);')
    search_terms.append(fr'(lea|mov|and) \[?{any_reg}\]?, 0;')

    print(f"[bright_green][+][/bright_green] helpful regex for searching within {outfile}\n")

    for term in search_terms:
        og_print(f"egrep '{term}' {outfile} {len_sort}")


def main(args):
    if platform.system() == "Darwin":
        #Fix issue with Ropper in macOS -> AttributeError: 'Ropper' object has no attribute '__gatherGadgetsByEndings'
        multiprocessing.set_start_method('fork')

    g = Gadgetizer(args.files, args.bad_chars, args.output, args.arch, args.color)

    # JSON output mode
    if args.json:
        gadget_data = g.to_json()
        json_output = json.dumps(gadget_data, indent=2)

        if args.json_output:
            try:
                with open(args.json_output, "w") as f:
                    f.write(json_output)
                print(f"[bright_green][+][/bright_green] JSON output written to [bright_blue]{args.json_output}[/bright_blue]")
            except IOError as e:
                print(f"[bright_red][!][/bright_red] Failed to write JSON: {e}", file=sys.stderr)
        else:
            og_print(json_output)
        return

    # Normal output mode
    tree = Tree(
        f'[bright_green][+][/bright_green] Categorized gadgets :: {" ".join(sys.argv)}'
    )
    g.add_gadgets_to_tree(tree)

    print(tree)

    with open(f"{g.output}.clean", "w") as f:
        print(tree, file=f)

    print(
        f"[bright_green][+][/bright_green] Collection of all gadgets written to [bright_blue]{args.output}[/bright_blue]"
    )
    g.save()

    if args.skip_rp:
        return

    for file in args.files:
        if ":" in file:
            file, base = file.split(":")
            add_missing_gadgets(g.addresses, file, args.output, bad_bytes=args.bad_chars, base_address=base)
        else:
            add_missing_gadgets(g.addresses, file, args.output, bad_bytes=args.bad_chars)

    clean_up_all_gadgets(args.output)
    print_useful_regex(args.output, args.arch)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Searches for clean, categorized gadgets from a given list of files"
    )

    parser.add_argument(
        "-f",
        "--files",
        help="space separated list of files from which to pull gadgets (optionally, add base address (libspp.dll:0x10000000))",
        required=True,
        nargs="+",
    )
    parser.add_argument(
        "-b",
        "--bad-chars",
        help="space separated list of bad chars to omit from gadgets, e.g., 00 0a (default: empty)",
        default=[],
        nargs="+",
    )
    parser.add_argument(
        "-a",
        "--arch",
        choices=["x86", "x86_64"],
        help="architecture of the given file (default: x86)",
        default="x86",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="name of output file where all (uncategorized) gadgets are written (default: found-gadgets.txt)",
        default="found-gadgets.txt",
    )
    parser.add_argument(
        "-c",
        "--color",
        help="colorize gadgets in output (default: False)",
        action='store_true',
    )
    parser.add_argument(
        "-s",
        "--skip-rp",
        help="don't run rp++ to find additional gadgets (default: False)",
        action='store_true',
    )
    parser.add_argument(
        "-j",
        "--json",
        help="output gadgets in JSON format",
        action='store_true',
    )
    parser.add_argument(
        "--json-output",
        help="file to write JSON output (default: stdout)",
        metavar="FILE",
    )

    args = parser.parse_args()

    main(args)
