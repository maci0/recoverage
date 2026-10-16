"""Configured target file routes preserve project and per-target containment."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import quote

import pytest
from conftest import decode_body, wsgi_get
from coverage_fixture import write_coverage

from recoverage import server, ui


def _project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, target: str = "game") -> Path:
    root = tmp_path / "project"
    root.mkdir()
    (root / "reversed/game").mkdir(parents=True)
    (root / "binaries").mkdir()
    (root / "binaries/game.exe").write_bytes(b"game binary")
    (root / "rebrew-project.toml").write_text(
        f"[targets.{json.dumps(target)}]\nbinary = 'binaries/game.exe'\n"
        "[targets.other]\nbinary = 'binaries/other.exe'\n",
        encoding="utf-8",
    )
    snapshots = root / "exports"
    write_coverage(snapshots, target, {}, paths={"sourceRoot": "/reversed/game"})
    write_coverage(snapshots, "other", {}, paths={"sourceRoot": "/reversed/other"})
    monkeypatch.setenv("RECOVERAGE_SNAPSHOTS", str(snapshots))
    monkeypatch.setattr(server, "_project_dir", lambda: root)
    monkeypatch.setattr(ui, "_project_dir", lambda: root)
    return root


class TestTargetFileRoutes:
    @pytest.mark.parametrize("target", ["game", "my café #%"])
    def test_configured_roots_and_encoded_names(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: str
    ) -> None:
        root = _project(tmp_path, monkeypatch, target=target)
        (root / "reversed/game/café #%.c").write_bytes(b"int value = 7;\n")
        prefix = f"/files/{quote(target, safe='')}"
        status, headers, body = wsgi_get(prefix + "/source/" + quote("café #%.c"))
        assert status.startswith("200")
        assert decode_body(body, headers) == b"int value = 7;\n"
        status, headers, body = wsgi_get(prefix + "/binary")
        assert status.startswith("200")
        assert body == b"game binary"
        assert "default-src 'none'" in headers["Content-Security-Policy"]

    def test_targets_do_not_fall_back_to_another_source_or_binary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path, monkeypatch)
        (root / "reversed/game/main.c").write_bytes(b"game source")
        for path in (
            "/files/other/source/main.c",
            "/files/other/binary",
            "/files/unknown/source/main.c",
            "/files/unknown/binary",
        ):
            status, _, body = wsgi_get(path)
            assert status.startswith("404"), (path, status)
            assert b"game source" not in body and b"game binary" not in body

    @pytest.mark.parametrize(
        "path",
        [
            "../secret.c",
            "../../binaries/game.exe",
            "/binaries/game.exe",
            "C:secret.c",
            "C:/secret.c",
            "\\secret.c",
            "bad\x00.c",
        ],
    )
    def test_source_paths_cannot_escape_the_target(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, path: str
    ) -> None:
        root = _project(tmp_path, monkeypatch)
        (root / "reversed/secret.c").write_bytes(b"secret")
        status, _, _ = wsgi_get("/files/game/source/" + quote(path, safe=""))
        assert status.startswith(("403", "404")), status

    @pytest.mark.parametrize("escape_root", [False, True])
    def test_source_symlinks_cannot_escape(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, escape_root: bool
    ) -> None:
        root = _project(tmp_path, monkeypatch)
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.c").write_bytes(b"secret")
        if escape_root:
            (root / "reversed/game").rmdir()
            (root / "reversed/game").symlink_to(outside, target_is_directory=True)
        else:
            (root / "reversed/game/secret.c").symlink_to(outside / "secret.c")
        status, _, body = wsgi_get("/files/game/source/secret.c")
        assert status.startswith("403")
        assert body != b"secret"

    def test_binary_symlink_cannot_escape_project(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path, monkeypatch)
        secret = tmp_path / "secret.exe"
        secret.write_bytes(b"secret")
        (root / "binaries/game.exe").unlink()
        (root / "binaries/game.exe").symlink_to(secret)
        status, _, body = wsgi_get("/files/game/binary")
        assert status.startswith("404")
        assert body != b"secret"

    @pytest.mark.parametrize("source_root", [".", "./", "/.", "/reversed/root"])
    def test_source_root_cannot_expose_the_whole_project(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source_root: str
    ) -> None:
        root = _project(tmp_path, monkeypatch)
        (root / ".env").write_bytes(b"secret")
        (root / "reversed/root").symlink_to(root, target_is_directory=True)
        write_coverage(root / "exports", "game", {}, paths={"sourceRoot": source_root})
        status, _, body = wsgi_get("/files/game/source/.env")
        assert status.startswith("403")
        assert body != b"secret"

    @pytest.mark.parametrize("configured_exists", [False, True])
    def test_portable_binary_takes_precedence_over_incidental_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, configured_exists: bool
    ) -> None:
        root = _project(tmp_path, monkeypatch)
        (root / "binaries/snapshot.exe").write_bytes(b"snapshot binary")
        if not configured_exists:
            (root / "binaries/game.exe").unlink()
        write_coverage(
            root / "exports", "game", {}, paths={"originalDll": "/binaries/snapshot.exe"}
        )
        status, _, body = wsgi_get("/files/game/binary")
        assert status.startswith("200") and body == b"snapshot binary"

    def test_invalid_portable_binary_does_not_fall_back_to_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path, monkeypatch)
        write_coverage(root / "exports", "game", {}, paths={"originalDll": "../secret.exe"})
        status, _, body = wsgi_get("/files/game/binary")
        assert status.startswith("404") and body != b"game binary"

    def test_portable_binary_without_project_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path, monkeypatch)
        (root / "rebrew-project.toml").unlink()
        write_coverage(root / "exports", "game", {}, paths={"originalDll": "/binaries/game.exe"})
        status, _, body = wsgi_get("/files/game/binary")
        assert status.startswith("200") and body == b"game binary"

    @pytest.mark.parametrize("configured", [False, True])
    def test_portable_byte_slices_use_the_downloaded_binary(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, configured: bool
    ) -> None:
        root = _project(tmp_path, monkeypatch)
        if not configured:
            (root / "rebrew-project.toml").unlink()
        (root / "binaries/snapshot.exe").write_bytes(b"snapshot binary")
        write_coverage(
            root / "exports",
            "game",
            {".text": {"va": 0x1000, "size": 15, "fileOffset": 0, "cells": []}},
            paths={"originalDll": "/binaries/snapshot.exe"},
        )
        status, headers, body = wsgi_get("/files/game/binary")
        assert status.startswith("200")
        downloaded = decode_body(body, headers)
        status, headers, body = wsgi_get("/api/targets/game/sections/.text/bytes?offset=0&size=4")
        assert status.startswith("200")
        assert json.loads(decode_body(body, headers))["raw"] == list(downloaded[:4])

    def test_portable_binary_path_edits_invalidate_cached_bytes_and_refusals(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path, monkeypatch)
        (root / "binaries/snapshot.exe").write_bytes(b"snapshot binary")
        for binary, expected in (
            ("../secret.exe", "404"),
            ("/binaries/snapshot.exe", "200"),
            ("../secret.exe", "404"),
        ):
            write_coverage(
                root / "exports",
                "game",
                {".text": {"va": 0x1000, "size": 15, "fileOffset": 0, "cells": []}},
                paths={"originalDll": binary},
            )
            status, headers, body = wsgi_get(
                "/api/targets/game/sections/.text/bytes?offset=0&size=4"
            )
            assert status.startswith(expected)
            if expected == "200":
                assert json.loads(decode_body(body, headers))["raw"] == list(b"snap")

    @pytest.mark.parametrize(
        "binary",
        [
            "../secret.exe",
            "//evil.example/x",
            "C:/secret.exe",
            "bad\x00.exe",
            "/binaries/escape.exe",
        ],
    )
    def test_portable_binary_path_is_contained(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, binary: str
    ) -> None:
        root = _project(tmp_path, monkeypatch)
        (root / "rebrew-project.toml").unlink()
        secret = tmp_path / "secret.exe"
        secret.write_bytes(b"secret")
        (root / "binaries/escape.exe").symlink_to(secret)
        write_coverage(root / "exports", "game", {}, paths={"originalDll": binary})
        status, _, body = wsgi_get("/files/game/binary")
        assert status.startswith("404") and body != b"secret"

    @pytest.mark.parametrize(
        "source_root", ["/reversed/\x00bad", "/reversed/loop", "../outside", "C:/outside"]
    )
    def test_invalid_source_root_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source_root: str
    ) -> None:
        root = _project(tmp_path, monkeypatch)
        (root / "reversed/loop").symlink_to("loop")
        write_coverage(root / "exports", "game", {}, paths={"sourceRoot": source_root})
        status, _, _ = wsgi_get("/files/game/source/main.c")
        # Non-strict resolution can leave an unreadable loop for the file server
        # to report missing; neither a path error nor an absent file may become 500.
        assert status.startswith(("403", "404"))

    def test_portable_binary_symlink_loop_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path, monkeypatch)
        (root / "rebrew-project.toml").unlink()
        (root / "binaries/loop.exe").symlink_to("loop.exe")
        write_coverage(root / "exports", "game", {}, paths={"originalDll": "/binaries/loop.exe"})
        status, _, _ = wsgi_get("/files/game/binary")
        assert status.startswith("404")

    def test_source_is_inert_compressed_and_revalidated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = _project(tmp_path, monkeypatch)
        raw = b"<script>alert('no')</script>\n" * 100
        (root / "reversed/game/page.html").write_bytes(raw)
        path = "/files/game/source/page.html"
        status, headers, body = wsgi_get(path, headers={"Accept-Encoding": "gzip"})
        assert status.startswith("200")
        assert decode_body(body, headers) == raw
        assert headers["Content-Encoding"] == "gzip"
        assert "sandbox" in headers["Content-Security-Policy"]
        status, _, body = wsgi_get(
            path, headers={"Accept-Encoding": "gzip", "If-None-Match": headers["Etag"]}
        )
        assert status.startswith("304") and not body
