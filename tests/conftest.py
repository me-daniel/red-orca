import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import uvicorn

from vsw.lab import create_app
from vsw.scope import approve_manifest


@pytest.fixture
def offlist_server():
    """A live origin that is deliberately absent from every manifest."""
    hits: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            hits.append(self.path)
            body = b"offlist"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield {"url": f"http://127.0.0.1:{server.server_address[1]}", "hits": hits}
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """Throwaway repo with one commit. Implementation runs in worktrees off it."""
    repo = tmp_path / "repo"
    repo.mkdir()

    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=str(repo), capture_output=True, text=True, check=True)

    git("init", "-q", "-b", "main")
    git("config", "user.email", "test@example.invalid")
    git("config", "user.name", "Test")
    (repo / "README.md").write_text("base\n", encoding="utf-8")
    git("add", "-A")
    git("commit", "-qm", "base")
    return repo


@pytest.fixture(scope="session")
def lab_server():
    config = uvicorn.Config(
        create_app(),
        host="127.0.0.1",
        port=0,
        log_level="warning",
        server_header=False,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 20
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.02)
    assert server.started, "lab server did not start"
    port = server.servers[0].sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=10)


@pytest.fixture
def manifest(tmp_path: Path, lab_server: str):
    """An approved loopback-only manifest for the test lab."""

    def build(
        origin: str = lab_server,
        profile: str = "lab",
        path_prefixes: list[str] | None = None,
        max_requests: int = 30,
        exclude_paths: list[str] | None = None,
    ) -> Path:
        path = tmp_path / "engagement.yaml"
        prefixes = path_prefixes or ["/vuln", "/clean"]
        body = "\n".join(
            [
                "id: test-engagement",
                "owner: tester",
                "approver: tester",
                "authorization_ref: unit test fixture",
                f"profile: {profile}",
                'expires_at: "2030-01-01T00:00:00Z"',
                "origins:",
                f"  - {origin}",
                "methods:",
                "  - GET",
                "path_prefixes:",
                *[f"  - {prefix}" for prefix in prefixes],
                "exclude_paths: " + ("[]" if not exclude_paths else ""),
                *[f"  - {item}" for item in (exclude_paths or [])],
                "mutation_allowed: false",
                f"max_requests: {max_requests}",
                "max_rps: 20.0",
                "max_wall_seconds: 120",
                "max_concurrency: 1",
                "approval:",
                "  approved: false",
                "  approved_by: null",
                "  approved_at: null",
                "  approved_manifest_sha256: null",
                "",
            ]
        )
        path.write_text(body, encoding="utf-8")
        approve_manifest(path, "tester")
        return path

    return build
