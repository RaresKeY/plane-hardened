"""Routing regression controls; run inside the restricted qualification container."""

import ast
import contextlib
import io
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from operator_config import absolute_directory, load_operator_config
import run_restricted


PROFILE = {
    "PLANE_QUALIFICATION_HOST": "test-user@qualification.example",
    "PLANE_QUALIFICATION_ROOT": "/srv/plane-qualification",
    "PLANE_QUALIFICATION_INTAKE_ROOT": "/srv/reviewed-intake",
    "SSH_AUTH_SOCK": "/tmp/test-agent.sock",
}
ROOT = Path(__file__).resolve().parent
LAUNCHERS = ("build_backend.py", "run_restricted.py", "run_javascript.py", "scan_backend.py")


class OperatorConfigTests(unittest.TestCase):
    def test_explicit_profile_and_ssh_guards(self):
        config = load_operator_config(PROFILE)
        self.assertEqual(config.root, PROFILE["PLANE_QUALIFICATION_ROOT"])
        self.assertEqual(config.ssh, [
            "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", PROFILE["PLANE_QUALIFICATION_HOST"]
        ])

    def test_no_implicit_destination(self):
        for profile in ({}, {"PLANE_QUALIFICATION_HOST": "example"}, {"PLANE_QUALIFICATION_ROOT": "/srv/tests"}):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                load_operator_config(profile)

    def test_ssh_alias_and_user_hosts(self):
        for host in ("qualification", "qualification.example", "test_user@qualification.example", "192.0.2.1"):
            with self.subTest(host=host):
                self.assertEqual(load_operator_config({**PROFILE, "PLANE_QUALIFICATION_HOST": host}).host, host)

    def test_reject_host_options_and_shell_syntax(self):
        for host in ("-oProxyCommand=evil", "host;id", "user@-o", "a@b@c", "host\nother", "host $(id)", "a/b"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                load_operator_config({**PROFILE, "PLANE_QUALIFICATION_HOST": host})

    def test_reject_unsafe_roots(self):
        for root in ("", "/", "relative", "/srv/../tmp", "/srv/./tmp", "/srv//tmp", "/srv/tmp/",
                     "/srv/a b", "/srv/a;id", "/srv/$(id)", "/srv/a:rw", "/srv/a\nb", "/srv/a'", "/srv/*"):
            with self.subTest(root=root), self.assertRaises(ValueError):
                absolute_directory(root)

    def test_valid_intake_directory(self):
        config = load_operator_config(PROFILE)
        self.assertEqual(config.dependency_directory("/srv/reviewed-intake/plane-js-qualified", PROFILE),
                         "/srv/reviewed-intake/plane-js-qualified")

    def test_intake_parent_requires_explicit_configuration(self):
        with self.assertRaises(ValueError):
            load_operator_config(PROFILE).dependency_directory("/srv/reviewed-intake/plane-js-qualified", {})

    def test_intake_boundary_and_traversal(self):
        for value in ("/srv/reviewed-intake-escape/plane-js-ok", "/srv/other/plane-js-ok",
                      "/srv/reviewed-intake/plane-js-ok/subdir", "/srv/reviewed-intake/other",
                      "/srv/reviewed-intake/../plane-js-ok", "/srv/reviewed-intake/plane-js-$(id)"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                load_operator_config(PROFILE).dependency_directory(value, PROFILE)

    def test_invalid_intake_parent(self):
        with self.assertRaises(ValueError):
            load_operator_config(PROFILE).dependency_directory(
                "/srv/reviewed-intake/plane-js-ok", {"PLANE_QUALIFICATION_INTAKE_ROOT": "/srv/../intake"}
            )

    def test_tools_lane_uses_configured_destination(self):
        with patch.dict(os.environ, PROFILE, clear=True), patch.object(sys, "argv", ["run_restricted.py", "tools"]), \
                patch.object(run_restricted.subprocess, "run") as run:
            run.return_value.returncode = 0
            self.assertEqual(run_restricted.main(), 0)
            args, kwargs = run.call_args
        self.assertEqual(args[0], load_operator_config(PROFILE).ssh + ["python3 -"])
        program = ast.parse(kwargs["input"])
        config = ast.literal_eval(program.body[-1].value.args[0])
        self.assertEqual(config["root"], PROFILE["PLANE_QUALIFICATION_ROOT"])
        self.assertEqual(config["lane"], "tools")

    def test_all_launcher_help_works_without_profile(self):
        for name in LAUNCHERS:
            with self.subTest(launcher=name):
                result = subprocess.run([sys.executable, str(ROOT / name), "--help"],
                                        env={"PATH": os.defpath}, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_role_lane_binds_its_controller_and_source_snapshot(self):
        with patch.dict(os.environ, PROFILE, clear=True), patch.object(
                sys, "argv", ["run_restricted.py", "roles", "--backend-image", "a" * 64]), \
                patch.object(run_restricted, "stage", return_value="reviewed-source") as stage, \
                patch.object(run_restricted.subprocess, "run") as run:
            run.return_value.returncode = 0
            self.assertEqual(run_restricted.main(), 0)
            program = run.call_args.kwargs["input"]
        stage.assert_called_once()
        compile(program, "roles:remote", "exec")
        tree = ast.parse(program)
        config = ast.literal_eval(tree.body[-1].value.args[0])
        self.assertEqual(config["source_digest"], "reviewed-source")
        self.assertEqual(tree.body[-1].value.args[1].id, "run_role_fixture")
        self.assertTrue(any(isinstance(node, ast.FunctionDef) and node.name == "run_role_fixture"
                            for node in tree.body))

    def test_all_launchers_fail_closed_without_profile(self):
        arguments = (("--wheels", "/absent", "--manifest", "/absent", "--zlib-deb", "/absent"),
                     ("tools",), ("all", "--dependencies", "/absent", "--manifest", "/absent", "--image", "a" * 64),
                     ("a" * 64,))
        for name, args in zip(LAUNCHERS, arguments):
            with self.subTest(launcher=name):
                result = subprocess.run([sys.executable, str(ROOT / name), *args],
                                        env={"PATH": os.defpath}, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertIn(b"Set PLANE_QUALIFICATION_HOST and PLANE_QUALIFICATION_ROOT", result.stderr)

    def test_missing_agent_does_not_start_remote_process(self):
        profile = {key: value for key, value in PROFILE.items() if key != "SSH_AUTH_SOCK"}
        with patch.dict(os.environ, profile, clear=True), patch.object(sys, "argv", ["run_restricted.py", "tools"]), \
                patch.object(run_restricted.subprocess, "run") as run, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                run_restricted.main()
            self.assertEqual(error.exception.code, 2)
            run.assert_not_called()

    def test_embedded_programs_remain_self_contained(self):
        for name in ("build_backend.py", "scan_backend.py"):
            tree = ast.parse((ROOT / name).read_text())
            programs = [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)
                        and isinstance(node.value, str) and "import " in node.value and "\n" in node.value]
            self.assertTrue(programs)
            for program in programs:
                with self.subTest(launcher=name):
                    compile(program, name + ":remote", "exec")
                    self.assertNotIn("from operator_config", program)


if __name__ == "__main__":
    unittest.main()
