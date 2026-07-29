import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from trustai.chain import EvidenceChain
from trustai.ingest import INGEST_ENTRY_TYPE
from trustai.server import serve


ROOT = Path(__file__).resolve().parents[1]


def _bundled_node_candidates() -> list[str]:
    candidates: list[str] = []
    win_users = Path("/mnt/c/Users")
    if win_users.exists():
        candidates.extend(
            str(path)
            for path in win_users.glob(
                "*/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe"
            )
        )
    candidates.append(
        str(Path.home() / ".cache" / "codex-runtimes" / "codex-primary-runtime" / "dependencies" / "node" / "bin" / "node.exe")
    )
    return candidates


NODE_CANDIDATES = [shutil.which("node"), os.environ.get("TRUSTAI_NODE"), *_bundled_node_candidates()]


def _node_major(candidate: str) -> int | None:
    try:
        result = subprocess.run(
            [candidate, "--version"],
            text=True,
            capture_output=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    version = result.stdout.strip().lstrip("v")
    try:
        return int(version.split(".", 1)[0])
    except (TypeError, ValueError):
        return None


def _node_path() -> str | None:
    for candidate in NODE_CANDIDATES:
        if candidate and Path(candidate).exists() and (_node_major(candidate) or 0) >= 16:
            return candidate
    return None


def _node_is_windows_exe(candidate: str) -> bool:
    return candidate.lower().endswith(".exe") and candidate.startswith("/mnt/")


def _wsl_host_for_windows() -> str:
    result = subprocess.run(["hostname", "-I"], text=True, capture_output=True, timeout=5)
    if result.returncode != 0:
        return "127.0.0.1"
    return result.stdout.split()[0]


class TypeScriptSDKTests(unittest.TestCase):
    @unittest.skipUnless(_node_path(), "Node.js >= 16 runtime is not available")
    def test_typescript_sdk_posts_events_to_ingest_api(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "typescript-sdk-chain.json"
            node_path = _node_path()
            bind_host = "0.0.0.0" if _node_is_windows_exe(node_path) else "127.0.0.1"
            endpoint_host = _wsl_host_for_windows() if _node_is_windows_exe(node_path) else "127.0.0.1"
            httpd = serve(bind_host, 0, str(state_path), "ts-sdk-server")
            _, port = httpd.server_address
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                env = {
                    **os.environ,
                    "TRUSTAI_ENDPOINT": f"http://{endpoint_host}:{port}",
                }
                wslenv = [entry for entry in env.get("WSLENV", "").split(":") if entry]
                if "TRUSTAI_ENDPOINT/u" not in wslenv:
                    wslenv.append("TRUSTAI_ENDPOINT/u")
                env["WSLENV"] = ":".join(wslenv)
                result = subprocess.run(
                    [
                        node_path,
                        str(ROOT / "sdk" / "typescript" / "test" / "sdk.test.mjs"),
                        env["TRUSTAI_ENDPOINT"],
                    ],
                    cwd=ROOT,
                    env=env,
                    text=True,
                    capture_output=True,
                    timeout=20,
                )
            finally:
                httpd.shutdown()
                httpd.server_close()
                thread.join(timeout=5)

            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            chain = EvidenceChain.load(state_path, tenant_id="ts-sdk-server")
            self.assertEqual(5, len(chain.entries))
            self.assertTrue(all(entry["entry_type"] == INGEST_ENTRY_TYPE for entry in chain.entries))
            self.assertEqual(
                [
                    "gen_ai.agent.decision",
                    "gen_ai.tool.call",
                    "gen_ai.tool.call",
                    "gen_ai.agent.decision",
                    "gen_ai.tool.call",
                ],
                [entry["payload"]["event"]["event_name"] for entry in chain.entries],
            )
            self.assertEqual(
                "batch_place_shadow_order",
                chain.entries[-1]["payload"]["event"]["attributes"]["tool.name"],
            )
            self.assertTrue(chain.verify_all().ok)


if __name__ == "__main__":
    unittest.main()
