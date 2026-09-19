"""Publication boundaries, without a stand, network or package installation."""

from pathlib import Path
import shutil
import subprocess
import pytest

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 developers may install tomli.
    tomllib = None


ROOT = Path(__file__).resolve().parents[1]
PRIVATE_PATHS = (
    "stand.txt", "AGENTS.md", "AUDIT_MANSPIDER.md", "IMPROVEMENT_PLAN_MANSPIDER.md",
    "BASELINE_MANSPIDER.md", "ACCEPTANCE_STAND.md", "BENCHMARK_STAND.md",
    "CHAOS_TEST_STAND.md", "FINAL_COMPARISON_MANSPIDER.md", "LOCAL_EFFICIENCY.md",
    "benchmark-artifacts/scan.json", "benchmark-corpus/file.txt", "dist/old.whl",
    "new-unreviewed-report.md", "tools/New-ManspiderChaosCorpus.ps1",
    "testdata/test.docx", "testdata/content-rules.json", "tools/build_benchmark_seed.py",
    "tools/compare_scan_states.py", "tools/benchmark_web_viewer.py",
    "tools/benchmark_analysis_state.py", "tools/fixtures/LICENSE.pandas",
    "PUBLICATION.md", "RULES.md", "DEFAULT_RULES.md", "WEB_VIEWER.md", "RULE_COVERAGE.md",
    "CHANGES_FROM_ORIGINAL_MANSPIDER.md", "RULE_PACK_2_4.md", "RULE_PACK_2_5.md",
    "RULE_PACK_2_6.md", "RULE_PACK_2_7.md",
    "tools/validate_chaos_results.py", "man_spider/stand.txt", "man_spider/.env",
    "man_spider/loot/secret.txt", "man_spider/logs/scan.txt",
    "man_spider/.env.local", "man_spider/session.sqlite3", "man_spider/session.sqlite3-wal",
    "man_spider/session.sqlite3.lock", "man_spider/session.review-wal",
    "man_spider/session.review.lock", "man_spider/session.db", "man_spider/session.log",
    "man_spider/session.smb-metrics.json", "man_spider/session.unclassified-files.jsonl",
    "tests/__pycache__/test_publication.cpython-312.pyc",
)


@pytest.mark.skipif(not shutil.which("git"), reason="git required for ignore contract")
def test_git_excludes_private_and_unreviewed_files(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, timeout=10)
    shutil.copyfile(ROOT / ".gitignore", tmp_path / ".gitignore")
    result = subprocess.run(
        ["git", "-c", "core.excludesFile=/dev/null", "check-ignore", "--no-index", "--stdin"],
        cwd=tmp_path, input="\n".join(PRIVATE_PATHS) + "\n", text=True,
        capture_output=True, check=True, timeout=10,
    )
    assert set(result.stdout.splitlines()) == set(PRIVATE_PATHS)


@pytest.mark.skipif(not shutil.which("git"), reason="git required for ignore contract")
def test_git_admits_required_public_files(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True, timeout=10)
    shutil.copyfile(ROOT / ".gitignore", tmp_path / ".gitignore")
    paths = (
        "README.md", "LICENSE", "pyproject.toml", "uv.lock", "CHANGES_FROM_ORIGINAL_MANSPIDER_EN.md",
        "man_spider/manspider.py", "man_spider/builtin_rules_v3.json",
        "man_spider/web_static/app.js", "tests/test_publication.py",
    )
    result = subprocess.run(
        ["git", "-c", "core.excludesFile=/dev/null", "check-ignore", "--no-index", "--stdin"],
        cwd=tmp_path, input="\n".join(paths) + "\n", text=True, capture_output=True, timeout=10,
    )
    assert result.returncode == 1, result.stdout + result.stderr
    assert not result.stdout


def test_build_targets_are_explicit_and_retain_required_source():
    parser = tomllib if tomllib is not None else pytest.importorskip("tomli")
    project = parser.loads((ROOT / "pyproject.toml").read_text())
    build = project["tool"]["hatch"]["build"]
    assert build["targets"]["wheel"]["packages"] == ["man_spider"]
    selected = set(build["targets"]["sdist"]["only-include"])
    assert {"tests", "man_spider", "LICENSE", "README.md", "CHANGES_FROM_ORIGINAL_MANSPIDER_EN.md"} <= selected
    assert not {"testdata", "tools", "tools/fixtures", "PUBLICATION.md", "RULES.md"} & selected
    assert all((ROOT / entry).exists() for entry in selected)
    assert not selected.intersection(PRIVATE_PATHS)
    assert {"**/stand.txt", "**/.env", "**/*.sqlite3-*", "**/*.review-*", "**/*.log"} <= set(build["exclude"])
    assert project["project"]["urls"]["Repository"] == "https://github.com/ShAmRoWw/MANSPIDER"
    assert {author["name"] for author in project["project"]["authors"]} >= {"TheTechromancer", "ShAmRoWw"}


def test_docker_context_admits_only_runtime_build_inputs():
    patterns = [line.strip() for line in (ROOT / ".dockerignore").read_text().splitlines()
                if line.strip() and not line.startswith("#")]
    assert patterns[0] == "**"
    assert {line for line in patterns if line.startswith("!")} == {
        "!Dockerfile", "!.dockerignore", "!pyproject.toml", "!uv.lock", "!README.md",
        "!LICENSE", "!man_spider/", "!man_spider/**",
    }
    assert patterns.index("**/stand.txt") > patterns.index("!man_spider/**")
    assert "COPY pyproject.toml uv.lock README.md LICENSE ./" in (ROOT / "Dockerfile").read_text()


def test_third_party_fixture_carries_full_license_notice():
    if not (ROOT / "tools/fixtures/pandas-test1.xlsb.xz.b64").is_file():
        pytest.skip("The optional local-only fixture is not distributed with public source")
    license_text = (ROOT / "tools/fixtures/LICENSE.pandas").read_text()
    assert "BSD 3-Clause License" in license_text
    assert "Copyright (c) 2008-2011" in license_text
    assert "THIS SOFTWARE IS PROVIDED" in license_text
    assert "LICENSE.pandas" in (ROOT / "tools/fixtures/README.md").read_text()
