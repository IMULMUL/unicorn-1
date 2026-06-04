import contextlib
import importlib.util
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UNICORN_PATH = ROOT / "unicorn.py"


class UnicornRegressionTests(unittest.TestCase):
    def run_unicorn(self, work_dir, *args):
        result = subprocess.run(
            [sys.executable, str(UNICORN_PATH), *args],
            cwd=work_dir,
            env={**os.environ, "TERM": "dumb"},
            text=True,
            capture_output=True,
            input="\n",
            timeout=10,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr + result.stdout[-1000:])
        return result

    def test_unicorn_compiles_without_syntax_warnings(self):
        command = [
            sys.executable,
            "-W",
            "always::SyntaxWarning",
            "-c",
            (
                "source = open('unicorn.py', encoding='utf-8').read();"
                "compile(source, 'unicorn.py', 'exec')"
            ),
        ]

        result = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("SyntaxWarning", result.stderr)

    def test_shellcode_generation_does_not_replace_add_type_result(self):
        sys.dont_write_bytecode = True
        original_argv = sys.argv[:]
        sys.argv = ["unicorn.py"]
        try:
            spec = importlib.util.spec_from_file_location("unicorn_under_test", UNICORN_PATH)
            module = importlib.util.module_from_spec(spec)
            with contextlib.redirect_stdout(io.StringIO()):
                spec.loader.exec_module(module)
                powershell_code = module.gen_shellcode_attack(
                    "0xfc,0xe8",
                    "cobaltstrike",
                    "cobaltstrike",
                )
        finally:
            sys.argv = original_argv

        self.assertIn("Add-Type -pass -m", powershell_code)
        self.assertIsNone(
            re.search(r"Add-Type[^;]+;(\$[A-Za-z]{2})=\1\.replace\(", powershell_code),
            powershell_code,
        )

    def test_cert_attack_writes_plain_base64_certificate(self):
        with tempfile.TemporaryDirectory() as work_dir:
            work_path = Path(work_dir)
            (work_path / "sample.bin").write_bytes(b"abc123")

            self.run_unicorn(work_path, "sample.bin", "crt")

            certificate = work_path / "decode_attack" / "encoded_attack.crt"
            self.assertEqual(
                certificate.read_text(),
                "-----BEGIN CERTIFICATE-----\nYWJjMTIz\n-----END CERTIFICATE-----",
            )

    def test_invalid_missing_arguments_exit_nonzero(self):
        with tempfile.TemporaryDirectory() as work_dir:
            result = subprocess.run(
                [sys.executable, str(UNICORN_PATH), "windows/meterpreter/reverse_tcp"],
                cwd=work_dir,
                env={**os.environ, "TERM": "dumb"},
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            self.assertIn("right syntax", result.stdout)

    def test_shellcode_hta_modifier_generates_only_hta_attack(self):
        with tempfile.TemporaryDirectory() as work_dir:
            work_path = Path(work_dir)
            (work_path / "shellcode.txt").write_text("0xfc,0xe8,0x82,0x00")

            self.run_unicorn(work_path, "shellcode.txt", "shellcode", "hta")

            self.assertTrue((work_path / "hta_attack" / "Launcher.hta").is_file())
            self.assertTrue((work_path / "hta_attack" / "index.html").is_file())
            self.assertFalse((work_path / "powershell_attack.txt").exists())

    def test_shellcode_ms_modifier_generates_settingcontent_attack(self):
        with tempfile.TemporaryDirectory() as work_dir:
            work_path = Path(work_dir)
            shutil.copytree(ROOT / "templates", work_path / "templates")
            (work_path / "shellcode.txt").write_text("0xfc,0xe8,0x82,0x00")

            self.run_unicorn(work_path, "shellcode.txt", "shellcode", "ms")

            self.assertTrue((work_path / "hta_attack" / "Launcher.hta").is_file())
            self.assertTrue((work_path / "hta_attack" / "index.html").is_file())
            self.assertTrue(
                (work_path / "hta_attack" / "Standalone_NoASR.SettingContent-ms").is_file()
            )


if __name__ == "__main__":
    unittest.main()
