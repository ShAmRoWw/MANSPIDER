"""Skip unpublished fixture trees without hiding incomplete local fixtures."""

from pathlib import Path

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def require_private_directory(name, *, module=False):
    """Only an entirely absent private tree is optional; its contents are not."""
    directory = PROJECT_ROOT / name
    try:
        directory.lstat()
    except FileNotFoundError:
        pytest.skip(
            f"Optional local {name}/ directory is not included in the public repository",
            allow_module_level=module,
        )
    return directory
