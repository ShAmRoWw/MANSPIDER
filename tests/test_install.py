"""Installer contract checks without downloading packages or changing shell files."""

import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import textwrap

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")
pytestmark = pytest.mark.skipif(sys.platform != "linux" or not BASH, reason="Linux Bash installer")
CONSTRAINTS = "installer-test-dependency==1.2.3\n"


def option_value(arguments, option):
    for index, argument in enumerate(arguments):
        if argument == option:
            return arguments[index + 1]
        if argument.startswith(option + "="):
            return argument.split("=", 1)[1]
    return None


class InstallerSandbox:
    def __init__(self, root):
        self.root = root
        self.project = root / "checkout with spaces"
        self.project.mkdir()
        for filename in ("install.sh", "pyproject.toml", "uv.lock"):
            shutil.copyfile(PROJECT_ROOT / filename, self.project / filename)
        self.cwd = root / "unrelated working directory"
        self.cwd.mkdir()
        self.temporary = root / "temporary files"
        self.temporary.mkdir()
        self.tool_bin = root / "tool bin"
        self.tool_bin.mkdir()
        self.stub_bin = root / "stub executables"
        self.stub_bin.mkdir()
        self.system_bin = root / "system executables"
        self.system_bin.mkdir()
        # A restricted PATH makes missing-uv tests independent of the host.
        for command in ("bash", "basename", "cat", "dirname", "env", "mktemp", "readlink", "realpath", "rm", "rmdir", "uname"):
            executable = shutil.which(command)
            if executable:
                (self.system_bin / command).symlink_to(executable)
        self.log_path = root / "uv-calls.jsonl"
        self.env = os.environ.copy()
        self.env.pop("BASH_ENV", None)
        self.env.pop("ENV", None)
        self.env.update(
            TMPDIR=str(self.temporary),
            PATH=os.pathsep.join((str(self.stub_bin), str(self.system_bin))),
            SHELL=BASH,
            INSTALL_TEST_LOG=str(self.log_path),
            INSTALL_TEST_BIN=str(self.tool_bin),
            INSTALL_TEST_CONSTRAINTS=CONSTRAINTS,
        )
        stub = self.stub_bin / "uv"
        stub.write_text(
            f"#!{sys.executable}\n"
            + textwrap.dedent(
                r'''
                import json
                import os
                from pathlib import Path
                import sys

                arguments = sys.argv[1:]
                action = arguments[0] if arguments else ""
                if action == "tool" and len(arguments) > 1:
                    action = "tool " + arguments[1]

                def option(name):
                    for index, argument in enumerate(arguments):
                        if argument == name:
                            return arguments[index + 1]
                        if argument.startswith(name + "="):
                            return argument.split("=", 1)[1]
                    return None

                entry = {"args": arguments, "action": action, "cwd": os.getcwd()}
                if action == "export":
                    output = option("--output-file") or option("-o")
                    if output:
                        Path(output).write_text(os.environ["INSTALL_TEST_CONSTRAINTS"])
                        entry["constraints_path"] = str(Path(output).resolve())
                    else:
                        sys.stdout.write(os.environ["INSTALL_TEST_CONSTRAINTS"])
                if action == "tool install":
                    constraints = option("--constraints") or option("-c")
                    if constraints:
                        entry["constraints_path"] = str(Path(constraints).resolve())
                        entry["constraints"] = Path(constraints).read_text()
                with open(os.environ["INSTALL_TEST_LOG"], "a", encoding="utf-8") as stream:
                    stream.write(json.dumps(entry) + "\n")
                if action == os.environ.get("INSTALL_TEST_FAIL_ACTION"):
                    print("stub uv failure: " + action, file=sys.stderr)
                    sys.exit(23)
                if action == "tool dir":
                    print(os.environ["INSTALL_TEST_BIN"])
                elif action == "tool install" and os.environ.get("INSTALL_TEST_CONFLICT"):
                    if "--force" not in arguments:
                        print("Executable already exists and is not managed by uv", file=sys.stderr)
                        sys.exit(24)
                    Path(os.environ["INSTALL_TEST_CONFLICT"]).write_text("unexpected overwrite")
                elif action not in ("export", "tool install", "tool update-shell"):
                    print("Unexpected stub invocation: " + repr(arguments), file=sys.stderr)
                    sys.exit(25)
                '''
            ),
            encoding="utf-8",
        )
        stub.chmod(0o755)

    def run(self, *arguments):
        return subprocess.run(
            [BASH, str(self.project / "install.sh"), *arguments],
            cwd=self.cwd,
            env=self.env,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )

    def calls(self):
        if not self.log_path.exists():
            return []
        return [json.loads(line) for line in self.log_path.read_text(encoding="utf-8").splitlines()]

    def assert_temporaries_removed(self):
        assert not list(self.temporary.iterdir())
        for call in self.calls():
            if "constraints_path" in call:
                assert not Path(call["constraints_path"]).exists()


@pytest.fixture
def installer(tmp_path):
    return InstallerSandbox(tmp_path)


def test_install_uses_locked_web_dependencies_and_absolute_noneditable_project(installer):
    originals = {
        filename: ((installer.project / filename).read_bytes(), (installer.project / filename).stat().st_mtime_ns)
        for filename in ("pyproject.toml", "uv.lock")
    }
    result = installer.run()
    assert result.returncode == 0, result.stdout + result.stderr
    calls = installer.calls()
    exports = [call for call in calls if call["action"] == "export"]
    installs = [call for call in calls if call["action"] == "tool install"]
    assert len(exports) == len(installs) == 1
    export, install = exports[0], installs[0]
    assert calls.index(export) < calls.index(install)
    export_args = export["args"]
    assert {"--locked", "--no-dev", "--no-emit-project", "--no-hashes"} <= set(export_args)
    assert option_value(export_args, "--extra") == "web"
    assert option_value(export_args, "--format") == "requirements.txt"
    assert option_value(export_args, "--python") == "3.12"
    export_project = option_value(export_args, "--project") or option_value(export_args, "--directory")
    assert export_project == str(installer.project) or export["cwd"] == str(installer.project)
    install_args = install["args"]
    assert option_value(install_args, "--python") == "3.12"
    assert option_value(install_args, "--reinstall-package") == "man-spider"
    assert str(installer.project) + "[web]" in install_args
    assert "--force" not in install_args
    assert "--editable" not in install_args
    assert install["constraints"] == CONSTRAINTS
    assert any(call["args"] == ["tool", "dir", "--bin"] for call in calls)
    for filename, original in originals.items():
        path = installer.project / filename
        assert (path.read_bytes(), path.stat().st_mtime_ns) == original
    installer.assert_temporaries_removed()


@pytest.mark.parametrize("already_on_path", [False, True])
def test_shell_setup_only_when_tool_bin_is_missing_from_path(installer, already_on_path):
    if already_on_path:
        installer.env["PATH"] += os.pathsep + str(installer.tool_bin)
    result = installer.run()
    assert result.returncode == 0, result.stdout + result.stderr
    calls = installer.calls()
    updates = [call for call in calls if call["action"] == "tool update-shell"]
    assert len(updates) == (0 if already_on_path else 1)
    if updates:
        install_index = next(index for index, call in enumerate(calls) if call["action"] == "tool install")
        assert calls.index(updates[0]) > install_index
    installer.assert_temporaries_removed()


def test_similar_path_component_does_not_count_as_tool_bin(installer):
    installer.env["PATH"] += os.pathsep + str(installer.tool_bin) + "-other"
    result = installer.run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert any(call["action"] == "tool update-shell" for call in installer.calls())


@pytest.mark.parametrize("argument", ["--help", "-h"])
def test_help_does_not_require_uv(installer, argument):
    installer.env["PATH"] = str(installer.system_bin)
    result = installer.run(argument)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "usage" in (result.stdout + result.stderr).lower()
    assert not installer.calls()


@pytest.mark.parametrize("arguments", [("--unknown",), ("another-directory",), ("--help", "extra")])
def test_unrecognized_arguments_fail_before_running_uv(installer, arguments):
    result = installer.run(*arguments)
    assert result.returncode != 0
    assert not installer.calls()


def test_missing_uv_fails_with_actionable_message(installer):
    installer.env["PATH"] = str(installer.system_bin)
    result = installer.run()
    assert result.returncode != 0
    assert "uv" in (result.stdout + result.stderr).lower()
    assert not installer.calls()


@pytest.mark.parametrize("filename", ["pyproject.toml", "uv.lock"])
def test_missing_project_metadata_fails_before_uv(installer, filename):
    (installer.project / filename).unlink()
    result = installer.run()
    assert result.returncode != 0
    assert filename in result.stdout + result.stderr
    assert not installer.calls()


@pytest.mark.parametrize("action", ["export", "tool install"])
def test_uv_failure_propagates_without_fallback_or_shell_changes(installer, action):
    installer.env["INSTALL_TEST_FAIL_ACTION"] = action
    result = installer.run()
    assert result.returncode == 23, result.stdout + result.stderr
    calls = installer.calls()
    assert sum(call["action"] == action for call in calls) == 1
    assert not any(call["action"] == "tool update-shell" for call in calls)
    if action == "export":
        assert not any(call["action"] == "tool install" for call in calls)
    installer.assert_temporaries_removed()


def test_repeated_runs_reinstall_only_the_project(installer):
    for _ in range(2):
        result = installer.run()
        assert result.returncode == 0, result.stdout + result.stderr
        installer.assert_temporaries_removed()
    installs = [call for call in installer.calls() if call["action"] == "tool install"]
    assert len(installs) == 2
    for call in installs:
        assert option_value(call["args"], "--reinstall-package") == "man-spider"
        assert "--reinstall" not in call["args"]
        assert "--force" not in call["args"]


def test_tool_directory_lookup_failure_is_fatal_and_cleans_constraints(installer):
    installer.env["INSTALL_TEST_FAIL_ACTION"] = "tool dir"
    result = installer.run()
    assert result.returncode == 23, result.stdout + result.stderr
    calls = installer.calls()
    assert sum(call["action"] == "tool install" for call in calls) == 1
    assert sum(call["action"] == "tool dir" for call in calls) == 1
    assert not any(call["action"] == "tool update-shell" for call in calls)
    installer.assert_temporaries_removed()


def assert_manual_path_export(output, tool_bin):
    exports = [line.strip() for line in output.splitlines() if line.strip().startswith("export PATH=")]
    assert exports, output
    assert shlex.split(exports[0]) == ["export", f"PATH={tool_bin}:$PATH"]


def test_shell_update_failure_preserves_success_and_explains_manual_path_setup(installer):
    installer.env["INSTALL_TEST_FAIL_ACTION"] = "tool update-shell"
    result = installer.run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "could not update" in result.stderr.lower()
    assert "installed" in result.stdout.lower()
    assert_manual_path_export(result.stdout, installer.tool_bin)
    calls = installer.calls()
    assert sum(call["action"] == "tool install" for call in calls) == 1
    assert sum(call["action"] == "tool update-shell" for call in calls) == 1
    installer.assert_temporaries_removed()


@pytest.mark.parametrize("executable", ["manspider", "manspider-web"])
def test_shadowing_command_is_preserved_with_warning_and_manual_path_setup(installer, executable):
    shadow = installer.stub_bin / executable
    shadow.write_text("#!/bin/sh\nexit 91\n", encoding="utf-8")
    shadow.chmod(0o755)
    before = (shadow.read_bytes(), shadow.stat().st_mtime_ns)
    installer.env["PATH"] += os.pathsep + str(installer.tool_bin)
    result = installer.run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "warning" in result.stderr.lower()
    assert executable in result.stderr
    assert str(shadow) in result.stderr
    assert_manual_path_export(result.stderr, installer.tool_bin)
    assert (shadow.read_bytes(), shadow.stat().st_mtime_ns) == before
    assert not any(call["action"] == "tool update-shell" for call in installer.calls())
    installer.assert_temporaries_removed()


def test_foreign_command_conflict_is_not_force_overwritten(installer):
    foreign = installer.tool_bin / "manspider"
    foreign.write_text("foreign executable, preserve me\n", encoding="utf-8")
    foreign.chmod(0o755)
    before = (foreign.read_bytes(), foreign.stat().st_mtime_ns)
    installer.env["INSTALL_TEST_CONFLICT"] = str(foreign)
    result = installer.run()
    assert result.returncode == 24, result.stdout + result.stderr
    assert (foreign.read_bytes(), foreign.stat().st_mtime_ns) == before
    assert not any(call["action"] == "tool update-shell" for call in installer.calls())
    assert sum(call["action"] == "tool install" for call in installer.calls()) == 1
    installer.assert_temporaries_removed()


def test_non_linux_host_is_rejected_before_uv(installer):
    uname = installer.stub_bin / "uname"
    uname.write_text("#!/bin/sh\nprintf 'Darwin\\n'\n", encoding="utf-8")
    uname.chmod(0o755)
    result = installer.run()
    assert result.returncode != 0
    assert "linux" in (result.stdout + result.stderr).lower()
    assert not installer.calls()
