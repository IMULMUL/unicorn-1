import contextlib
import importlib.util
import io
import os
import re
import subprocess
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))
UNICORN_PATH = os.path.join(ROOT, "unicorn.py")


class UnicornRegressionTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
