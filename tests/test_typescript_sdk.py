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
NODE_CANDIDATES = [
    shutil.which("node"),
    str(Path.home() / ".cache" / "codex-runtimes" / "codex-primary-runtime" / "dependencies" / "node" / "bin" / "node.exe"),
]


def _node_path() -> str | None:
    for candidate in NODE_CANDIDATES:
        if candidate and Path(candidate).exists():
            return candidate
    return None


class TypeScriptSDKTests(unittest.TestCase):
    @unittest.skipUnless(_node_path(), "Node.js runtime is not available")
    def test_typescript_sdk_posts_events_to_ingest_api(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            state_path = Path(tmp_dir) / "typescript-sdk-chain.json"
            httpd = serve("127.0.0.1", 0, str(state_path), "ts-sdk-server")
            host, port = httpd.server_address
            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            try:
                env = {
                    **os.environ,
                    "TRUSTAI_ENDPOINT": f"http://{host}:{port}",
                }
                result = subprocess.run(
                    [_node_path(), str(ROOT / "sdk" / "typescript" / "test" / "sdk.test.mjs")],
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
            self.assertEqual(3, len(chain.entries))
            self.assertTrue(all(entry["entry_type"] == INGEST_ENTRY_TYPE for entry in chain.entries))
            self.assertEqual(
                ["gen_ai.agent.decision", "gen_ai.tool.call", "gen_ai.tool.call"],
                [entry["payload"]["event"]["event_name"] for entry in chain.entries],
            )
            self.assertTrue(chain.verify_all().ok)


if __name__ == "__main__":
    unittest.main()
