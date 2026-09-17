import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from trustai.server import serve


class ServerInputPathTests(unittest.TestCase):
    def test_request_paths_cannot_escape_input_directory(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            input_dir = root / "inputs"
            input_dir.mkdir()
            outside = root / "secret.json"
            outside.write_text("{}", encoding="utf-8")
            symlink = input_dir / "linked.json"
            symlink.symlink_to(outside)
            server = serve(
                "127.0.0.1",
                0,
                str(root / "state.json"),
                "server-test",
                control_db_path=str(root / "control.sqlite"),
                approval_request_store_path=str(root / "approvals.json"),
                input_dir=str(input_dir),
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            host, port = server.server_address
            conn = http.client.HTTPConnection(host, port, timeout=5)
            try:
                requests = [
                    ("/v0/control/index", {"state_path": str(outside)}, "state_path is server configured"),
                    ("/v0/control/index", {"proof_pack_path": str(outside)}, "input path"),
                    ("/v0/control/index", {"production_replacement_artifact_path": str(outside)}, "input path"),
                    ("/v0/control/index", {"production_replacement_artifact_paths": [str(outside)]}, "input path"),
                    ("/v0/control/index", {"production_replacement_closure_path": str(outside)}, "input path"),
                    ("/v0/control/index", {"production_replacement_closure_paths": [str(outside)]}, "input path"),
                    ("/v0/verify", {"path": str(outside)}, "input path"),
                    ("/v0/verify", {"path": symlink.name}, "input path"),
                    ("/v0/verify", {"path": str(input_dir / ".." / "secret.json")}, "input path"),
                    (
                        "/v0/approval-requests/slack",
                        {"approval_request": {"id": "test"}, "contract_path": str(outside)},
                        "input path",
                    ),
                    (
                        "/v0/approval-callbacks/slack",
                        {"interaction": {}, "contract_path": str(outside)},
                        "input path",
                    ),
                    ("/v0/provider-lifecycle-operations", {"lifecycle_path": str(outside)}, "input path"),
                    ("/v0/insurer-risk", {"path": str(outside)}, "input path"),
                ]
                for route, payload, expected_error in requests:
                    with self.subTest(route=route, payload=payload):
                        conn.request(
                            "POST",
                            route,
                            body=json.dumps(payload),
                            headers={"Content-Type": "application/json"},
                        )
                        response = conn.getresponse()
                        data = json.loads(response.read().decode("utf-8"))
                        self.assertEqual(422, response.status, data)
                        self.assertIn(expected_error, data["error"])

                allowed = input_dir / "valid.json"
                allowed.write_text("{}", encoding="utf-8")
                conn.request(
                    "POST",
                    "/v0/verify",
                    body=json.dumps({"path": allowed.name}),
                    headers={"Content-Type": "application/json"},
                )
                response = conn.getresponse()
                data = json.loads(response.read().decode("utf-8"))
                self.assertEqual(422, response.status)
                self.assertNotIn("input path", str(data))
            finally:
                conn.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
