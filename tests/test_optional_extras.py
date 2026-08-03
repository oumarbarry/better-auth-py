"""The plugins_ext package must import without the optional extras installed.

Caught in the wild: the v0.5.0 wheel without [passkey] crashed on
`from better_auth.plugins_ext import UsernamePlugin` because the package
eagerly imported passkey.py, which imports webauthn unguarded.
"""

import subprocess
import sys

_BLOCKED_IMPORT_SCRIPT = """
import sys

class _BlockWebauthn:
    def find_spec(self, name, path=None, target=None):
        if name == "webauthn" or name.startswith("webauthn."):
            raise ModuleNotFoundError(f"No module named {name!r}")

sys.meta_path.insert(0, _BlockWebauthn())

from better_auth.plugins_ext import UsernamePlugin  # must import without webauthn

try:
    from better_auth.plugins_ext import PasskeyPlugin
except ModuleNotFoundError as e:
    assert "[passkey]" in str(e), f"error should name the extra: {e}"
else:
    raise SystemExit("PasskeyPlugin import should have failed without webauthn")

print("ok")
"""


def test_plugins_ext_imports_without_passkey_extra():
    result = subprocess.run(
        [sys.executable, "-c", _BLOCKED_IMPORT_SCRIPT],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "ok"
