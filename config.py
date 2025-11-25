"""
config.py - Configuration management for OSED scripts

Loads settings from ~/.osedrc or .osedrc in the current directory.
"""
import os
import json
from pathlib import Path
from typing import Dict, Any, Optional, List

# Default configuration
DEFAULTS = {
    # Bad characters commonly filtered
    "bad_chars": ["00"],

    # Default egghunter settings
    "egghunter": {
        "tag": "c0d3",
        "type": "ntaccess",  # or "seh"
        "format": "python"
    },

    # Default pattern settings
    "pattern": {
        "length": 1000,
        "charset": None  # Use default
    },

    # Default gadget finder settings
    "gadgets": {
        "arch": "x86",
        "output": "found-gadgets.txt",
        "color": False,
        "skip_rp": False
    },

    # Network settings
    "network": {
        "timeout": 5.0,
        "retries": 3
    },

    # Output settings
    "output": {
        "format": "python",
        "varname": "payload"
    }
}


def find_config_file() -> Optional[Path]:
    """
    Find configuration file in standard locations.

    Searches in order:
    1. .osedrc in current directory
    2. ~/.osedrc
    3. ~/.config/osed/config.json

    Returns:
        Path to config file or None
    """
    locations = [
        Path.cwd() / ".osedrc",
        Path.home() / ".osedrc",
        Path.home() / ".config" / "osed" / "config.json"
    ]

    for loc in locations:
        if loc.exists():
            return loc

    return None


def load_config() -> Dict[str, Any]:
    """
    Load configuration from file.

    Returns:
        Configuration dictionary (defaults merged with file settings)
    """
    config = DEFAULTS.copy()

    config_file = find_config_file()
    if config_file:
        try:
            with open(config_file, 'r') as f:
                user_config = json.load(f)
                config = merge_config(config, user_config)
        except (json.JSONDecodeError, IOError) as e:
            print(f"[!] Warning: Failed to load config from {config_file}: {e}")

    return config


def merge_config(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge configuration dictionaries.

    Args:
        base: Base configuration
        override: Override values

    Returns:
        Merged configuration
    """
    result = base.copy()

    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_config(result[key], value)
        else:
            result[key] = value

    return result


def save_config(config: Dict[str, Any], path: Optional[Path] = None) -> bool:
    """
    Save configuration to file.

    Args:
        config: Configuration to save
        path: Path to save to (default: ~/.osedrc)

    Returns:
        True if successful
    """
    if path is None:
        path = Path.home() / ".osedrc"

    try:
        with open(path, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except IOError as e:
        print(f"[!] Failed to save config: {e}")
        return False


def get_bad_chars(config: Dict[str, Any] = None) -> List[str]:
    """
    Get bad characters from configuration.

    Args:
        config: Configuration dictionary (loads if not provided)

    Returns:
        List of bad character hex strings
    """
    if config is None:
        config = load_config()
    return config.get("bad_chars", DEFAULTS["bad_chars"])


def get_setting(key: str, default: Any = None, config: Dict[str, Any] = None) -> Any:
    """
    Get a setting value by dot-notation key.

    Args:
        key: Setting key (e.g., "egghunter.tag")
        default: Default value if not found
        config: Configuration dictionary

    Returns:
        Setting value or default

    Example:
        tag = get_setting("egghunter.tag")  # Returns "c0d3"
    """
    if config is None:
        config = load_config()

    parts = key.split(".")
    value = config

    for part in parts:
        if isinstance(value, dict) and part in value:
            value = value[part]
        else:
            return default

    return value


# Sample configuration file content
SAMPLE_CONFIG = """{
  "bad_chars": ["00", "0a", "0d"],

  "egghunter": {
    "tag": "w00t",
    "type": "ntaccess",
    "format": "python"
  },

  "pattern": {
    "length": 2000
  },

  "gadgets": {
    "arch": "x86",
    "output": "gadgets.txt",
    "color": true,
    "skip_rp": false
  },

  "network": {
    "timeout": 10.0,
    "retries": 5
  },

  "output": {
    "format": "python",
    "varname": "shellcode"
  }
}
"""


def create_sample_config(path: Optional[Path] = None) -> bool:
    """
    Create a sample configuration file.

    Args:
        path: Path to create (default: ./.osedrc)

    Returns:
        True if successful
    """
    if path is None:
        path = Path.cwd() / ".osedrc"

    if path.exists():
        print(f"[!] Config file already exists: {path}")
        return False

    try:
        with open(path, 'w') as f:
            f.write(SAMPLE_CONFIG)
        print(f"[+] Created sample config: {path}")
        return True
    except IOError as e:
        print(f"[!] Failed to create config: {e}")
        return False


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "init":
        create_sample_config()
    else:
        print("Configuration module for OSED scripts")
        print("")
        print("Usage:")
        print("  python config.py init    Create sample .osedrc file")
        print("")
        print("Config file locations (in order of priority):")
        print("  1. ./.osedrc")
        print("  2. ~/.osedrc")
        print("  3. ~/.config/osed/config.json")
        print("")
        print("Current config:")
        config = load_config()
        print(json.dumps(config, indent=2))
