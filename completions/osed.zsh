#compdef osed

# Zsh completion script for osed CLI
# Install: Add to fpath and run compinit
# Or source directly: source /path/to/osed.zsh

_osed() {
    local -a commands
    local -a pattern_commands
    local -a formats
    local -a archs

    commands=(
        'egghunter:Generate egghunter shellcode'
        'pattern:Cyclic pattern generator/finder'
        'gadgets:Find and categorize ROP gadgets'
        'info:Display tool information'
        'version:Show version information'
    )

    pattern_commands=(
        'create:Generate a cyclic pattern'
        'find:Find offset in cyclic pattern'
    )

    formats=(python c raw hex escaped)
    archs=(x86 x86_64)

    _arguments -C \
        '-V[Show version]' \
        '--version[Show version]' \
        '-h[Show help]' \
        '--help[Show help]' \
        '1:command:->command' \
        '*::arg:->args'

    case "$state" in
        command)
            _describe -t commands 'osed commands' commands
            ;;
        args)
            case "${words[1]}" in
                egghunter)
                    _arguments \
                        '-t[Tag to search for]:tag:' \
                        '--tag[Tag to search for]:tag:' \
                        '*-b[Bad characters]:bad char:' \
                        '*--bad-chars[Bad characters]:bad char:' \
                        '-s[Use SEH-based egghunter]' \
                        '--seh[Use SEH-based egghunter]' \
                        '-f[Output format]:format:(${formats})' \
                        '--format[Output format]:format:(${formats})' \
                        '-o[Output file]:file:_files' \
                        '--output[Output file]:file:_files' \
                        '-v[Verbose output]' \
                        '--verbose[Verbose output]' \
                        '-n[Variable name]:name:' \
                        '--varname[Variable name]:name:'
                    ;;
                pattern)
                    _arguments -C \
                        '1:pattern command:->pattern_cmd' \
                        '*::pattern arg:->pattern_args'

                    case "$state" in
                        pattern_cmd)
                            _describe -t pattern_commands 'pattern commands' pattern_commands
                            ;;
                        pattern_args)
                            case "${words[1]}" in
                                create)
                                    _arguments \
                                        '1:length:' \
                                        '-c[Character set]:charset:' \
                                        '--charset[Character set]:charset:' \
                                        '-o[Output file]:file:_files' \
                                        '--output[Output file]:file:_files'
                                    ;;
                                find)
                                    _arguments \
                                        '1:sequence:' \
                                        '-c[Character set]:charset:' \
                                        '--charset[Character set]:charset:'
                                    ;;
                            esac
                            ;;
                    esac
                    ;;
                gadgets)
                    _arguments \
                        '*-f[Binary files]:file:_files' \
                        '*--files[Binary files]:file:_files' \
                        '*-b[Bad characters]:bad char:' \
                        '*--bad-chars[Bad characters]:bad char:' \
                        '-a[Architecture]:arch:(${archs})' \
                        '--arch[Architecture]:arch:(${archs})' \
                        '-o[Output file]:file:_files' \
                        '--output[Output file]:file:_files' \
                        '-c[Colorize output]' \
                        '--color[Colorize output]' \
                        '-s[Skip rp++]' \
                        '--skip-rp[Skip rp++]' \
                        '-j[JSON output]' \
                        '--json[JSON output]' \
                        '--json-output[JSON output file]:file:_files'
                    ;;
            esac
            ;;
    esac
}

_osed "$@"
