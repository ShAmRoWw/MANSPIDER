"""Import regressions must run outside pytest's already populated module cache."""

from pathlib import Path
import subprocess
import sys

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = PROJECT_ROOT / "man_spider"
PRODUCTION_MODULES = tuple(
    ".".join(
        path.relative_to(PROJECT_ROOT).parts[:-1]
        if path.name == "__init__.py"
        else path.relative_to(PROJECT_ROOT).with_suffix("").parts
    )
    for path in sorted(PACKAGE_ROOT.rglob("*.py"))
)


def run_fresh_python(*arguments):
    result = subprocess.run(
        [sys.executable, "-B", *arguments],
        cwd=PROJECT_ROOT,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, (
        f"Fresh Python process exited with {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    return result


@pytest.mark.parametrize("module_name", PRODUCTION_MODULES)
def test_each_production_module_imports_in_a_fresh_process(module_name):
    run_fresh_python(
        "-c",
        "import importlib, sys; importlib.import_module(sys.argv[1])",
        module_name,
    )


@pytest.mark.parametrize("reverse", [False, True], ids=["forward", "reverse"])
def test_all_production_modules_import_together_in_either_order(reverse):
    module_names = tuple(reversed(PRODUCTION_MODULES)) if reverse else PRODUCTION_MODULES
    run_fresh_python(
        "-c",
        "import importlib, sys; [importlib.import_module(name) for name in sys.argv[1:]]",
        *module_names,
    )


def test_metrics_can_be_imported_and_write_a_report_before_the_scanner(tmp_path):
    run_fresh_python(
        "-c",
        """
import json
from pathlib import Path
import sys

from man_spider.metrics import SMBMetricsCollector, SMBMetricsEmitter, write_smb_metrics_report

# Collecting passive metrics should not initialize the scanner just to import
# the local report writer. The writer may import that helper on demand.
assert "man_spider.lib" not in sys.modules
assert "man_spider.manspider" not in sys.modules
destination = Path(sys.argv[1])
report = {"schema_version": 1, "hosts": []}
assert write_smb_metrics_report(report, destination) == destination
assert json.loads(destination.read_text(encoding="utf-8")) == report
assert list(destination.parent.glob("*.tmp")) == []

from man_spider.lib.smb import SMBMetricsEmitter as imported_by_smb
assert imported_by_smb is SMBMetricsEmitter
assert SMBMetricsCollector is not None
""",
        str(tmp_path / "metrics.json"),
    )


@pytest.mark.parametrize("entry_module", ["man_spider.manspider", "man_spider.web"])
def test_entrypoint_help_works_in_a_fresh_process(entry_module):
    result = run_fresh_python("-m", entry_module, "--help")
    assert "usage:" in result.stdout.lower()
