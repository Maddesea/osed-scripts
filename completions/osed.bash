# Bash completion script for osed CLI
# Install: source /path/to/osed.bash
# Or add to ~/.bashrc: source /path/to/osed-scripts/completions/osed.bash

_osed_completions() {
    local cur prev words cword
    _init_completion || return

    local commands="egghunter pattern gadgets info version"
    local pattern_cmds="create find"
    local formats="python c raw hex escaped"
    local archs="x86 x86_64"

    case "${prev}" in
        osed)
            COMPREPLY=($(compgen -W "${commands}" -- "${cur}"))
            return 0
            ;;
        pattern)
            COMPREPLY=($(compgen -W "${pattern_cmds}" -- "${cur}"))
            return 0
            ;;
        -f|--format)
            COMPREPLY=($(compgen -W "${formats}" -- "${cur}"))
            return 0
            ;;
        -a|--arch)
            COMPREPLY=($(compgen -W "${archs}" -- "${cur}"))
            return 0
            ;;
        --files)
            COMPREPLY=($(compgen -f -- "${cur}"))
            return 0
            ;;
        -o|--output)
            COMPREPLY=($(compgen -f -- "${cur}"))
            return 0
            ;;
    esac

    # Handle subcommand options
    case "${words[1]}" in
        egghunter)
            local opts="-t --tag -b --bad-chars -s --seh -f --format -o --output -v --verbose -n --varname -h --help"
            COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
            return 0
            ;;
        pattern)
            if [[ "${words[2]}" == "create" ]]; then
                local opts="-c --charset -o --output -h --help"
                COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
            elif [[ "${words[2]}" == "find" ]]; then
                local opts="-c --charset -h --help"
                COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
            fi
            return 0
            ;;
        gadgets)
            local opts="-f --files -b --bad-chars -a --arch -o --output -c --color -s --skip-rp -j --json --json-output -h --help"
            COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
            return 0
            ;;
    esac

    COMPREPLY=($(compgen -W "${commands}" -- "${cur}"))
}

complete -F _osed_completions osed
complete -F _osed_completions ./osed
