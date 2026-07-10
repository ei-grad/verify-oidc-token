import io
import json
import os
import runpy
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

from jwt.exceptions import InvalidTokenError

from verify_oidc_token import UNSAFE_FROM_TOKEN
from verify_oidc_token.cli import main


class TestCli(unittest.TestCase):
    def run_cli(self, argv, stdin_text=""):
        stdout = io.StringIO()
        stderr = io.StringIO()
        exit_code = 0
        with patch("sys.argv", ["verify-oidc-token"] + argv):
            with patch("sys.stdin", io.StringIO(stdin_text)):
                with redirect_stdout(stdout), redirect_stderr(stderr):
                    try:
                        main()
                    except SystemExit as e:
                        exit_code = e.code
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_missing_issuer_and_client_id_require_unsafe(self):
        for argv in (
            [],
            ["--issuer", "https://example.com"],
            ["--client-id", "cid"],
            ["--issuer", "", "--client-id", "cid"],
            ["--issuer", "https://example.com", "--client-id", ""],
        ):
            with self.subTest(argv=argv):
                exit_code, output, errors = self.run_cli(argv, stdin_text="tok")

                self.assertEqual(exit_code, 2)
                self.assertEqual(output, "")
                self.assertIn("--issuer and --client-id are required", errors)

    def test_unsafe_flag_defaults_to_unsafe_from_token(self):
        with patch("verify_oidc_token.cli.verify_token", return_value={"sub": "u"}) as mock_verify:
            exit_code, output, _ = self.run_cli(["--unsafe"], stdin_text="tok\n")

        self.assertEqual(exit_code, 0)
        mock_verify.assert_called_once_with("tok", UNSAFE_FROM_TOKEN, UNSAFE_FROM_TOKEN)
        self.assertEqual(json.loads(output), {"sub": "u"})

    def test_unsafe_flag_keeps_explicit_issuer(self):
        with patch("verify_oidc_token.cli.verify_token", return_value={}) as mock_verify:
            exit_code, _, _ = self.run_cli(
                ["--unsafe", "--issuer", "https://example.com"],
                stdin_text="tok",
            )

        self.assertEqual(exit_code, 0)
        mock_verify.assert_called_once_with("tok", "https://example.com", UNSAFE_FROM_TOKEN)

    def test_unsafe_flag_keeps_explicit_client_id(self):
        with patch("verify_oidc_token.cli.verify_token", return_value={}) as mock_verify:
            exit_code, _, _ = self.run_cli(
                ["--unsafe", "--client-id", "cid"],
                stdin_text="tok",
            )

        self.assertEqual(exit_code, 0)
        mock_verify.assert_called_once_with("tok", UNSAFE_FROM_TOKEN, "cid")

    def test_unsafe_flag_treats_empty_values_as_missing(self):
        with patch("verify_oidc_token.cli.verify_token", return_value={}) as mock_verify:
            exit_code, _, _ = self.run_cli(
                ["--unsafe", "--issuer", "", "--client-id", ""],
                stdin_text="tok",
            )

        self.assertEqual(exit_code, 0)
        mock_verify.assert_called_once_with("tok", UNSAFE_FROM_TOKEN, UNSAFE_FROM_TOKEN)

    def test_explicit_issuer_and_client_id(self):
        with patch("verify_oidc_token.cli.verify_token", return_value={}) as mock_verify:
            exit_code, _, errors = self.run_cli(
                ["--issuer", "https://example.com", "--client-id", "cid"],
                stdin_text="tok",
            )

        self.assertEqual(exit_code, 0)
        mock_verify.assert_called_once_with("tok", "https://example.com", "cid")
        self.assertEqual(errors, "")

    def test_verbose_enables_debug_logging(self):
        with patch("verify_oidc_token.cli.verify_token", return_value={}):
            with patch("verify_oidc_token.cli.logging.basicConfig") as mock_basic_config:
                exit_code, _, _ = self.run_cli(["--verbose", "--unsafe"], stdin_text="tok")

        self.assertEqual(exit_code, 0)
        mock_basic_config.assert_called_once()

    def test_dunder_main(self):
        # `python -m verify_oidc_token` runs __main__.py; exercise it in-process via runpy
        with patch("verify_oidc_token.cli.verify_token", return_value={"sub": "u"}):
            stdout = io.StringIO()
            with patch("sys.argv", ["verify-oidc-token", "--unsafe"]):
                with patch("sys.stdin", io.StringIO("tok")):
                    with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                        runpy.run_module("verify_oidc_token", run_name="__main__")

        self.assertEqual(json.loads(stdout.getvalue()), {"sub": "u"})

    def test_token_file(self):
        # A NamedTemporaryFile cannot be reopened by name on Windows while the original
        # handle is open, so write a regular file into a temporary directory instead.
        with tempfile.TemporaryDirectory() as tmpdir:
            token_path = os.path.join(tmpdir, "token.txt")
            with open(token_path, "w") as token_file:
                token_file.write("tok\n")
            with patch(
                "verify_oidc_token.cli.verify_token", return_value={"sub": "u"}
            ) as mock_verify:
                exit_code, output, _ = self.run_cli(["--unsafe", "--token-file", token_path])

        self.assertEqual(exit_code, 0)
        mock_verify.assert_called_once_with("tok", UNSAFE_FROM_TOKEN, UNSAFE_FROM_TOKEN)
        self.assertEqual(json.loads(output), {"sub": "u"})

    def test_unreadable_token_file(self):
        exit_code, output, _ = self.run_cli(["--unsafe", "--token-file", "/nonexistent/token.txt"])

        self.assertEqual(exit_code, 2)
        self.assertIn("Failed to read token file", json.loads(output)["error"])

    def test_invalid_token_error_reported_as_json(self):
        with patch(
            "verify_oidc_token.cli.verify_token",
            side_effect=InvalidTokenError("Signature has expired"),
        ):
            exit_code, output, _ = self.run_cli(["--unsafe"], stdin_text="tok")

        self.assertEqual(exit_code, 1)
        self.assertEqual(json.loads(output), {"error": "Signature has expired"})


if __name__ == "__main__":
    unittest.main()
