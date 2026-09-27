import json
import os
import stat
import sys

import pytest

from fimguard import baseline as bl
from fimguard import scan
from fimguard.__main__ import EXIT_CHANGES, EXIT_ERROR, EXIT_OK, EXIT_TAMPERED, main

KEY = "0123456789abcdef0123456789abcdef"
posix_only = pytest.mark.skipif(os.name == "nt", reason="permisos y nombres de archivo de POSIX")


@pytest.fixture
def site(tmp_path):
    root = tmp_path / "www"
    (root / "css").mkdir(parents=True)
    (root / "index.html").write_text("<h1>Hola</h1>")
    (root / "css" / "style.css").write_text("body { color: black }")
    (root / "app.log").write_text("línea 1\n")
    key_file = tmp_path / "clave.key"
    key_file.write_text(KEY)
    key_file.chmod(0o600)
    return root, tmp_path / "baseline.json", key_file


def run(*args):
    return main([str(a) for a in args])


def test_clean_check(site, capsys):
    root, baseline, key = site
    assert run("init", root, "-b", baseline, "-k", key) == EXIT_OK
    assert run("check", root, "-b", baseline, "-k", key) == EXIT_OK
    assert "Sin cambios" in capsys.readouterr().out


def test_detects_added_removed_and_modified(site, capsys):
    root, baseline, key = site
    run("init", root, "-b", baseline, "-k", key)
    (root / "index.html").write_text("<h1>Hackeado</h1>")
    (root / "css" / "style.css").unlink()
    (root / "shell.php").write_text("<?php // no debería estar aquí ?>")
    capsys.readouterr()
    assert run("check", root, "-b", baseline, "-k", key, "--json") == EXIT_CHANGES
    changes = {(c["kind"], c["path"]) for c in json.loads(capsys.readouterr().out)}
    assert changes == {("modified", "index.html"), ("removed", "css/style.css"), ("added", "shell.php")}


def test_update_accepts_and_lists_the_changes(site, capsys):
    root, baseline, key = site
    run("init", root, "-b", baseline, "-k", key)
    (root / "index.html").write_text("<h1>Versión 2</h1>")
    capsys.readouterr()
    assert run("update", root, "-b", baseline, "-k", key) == EXIT_OK
    out = capsys.readouterr().out
    assert "MODIFICADO" in out and "index.html" in out and "1 cambio(s) aceptados" in out
    assert run("check", root, "-b", baseline, "-k", key) == EXIT_OK


def test_init_does_not_overwrite_a_baseline(site, capsys):
    root, baseline, key = site
    run("init", root, "-b", baseline, "-k", key)
    (root / "index.html").write_text("<h1>Hackeado</h1>")
    assert run("init", root, "-b", baseline, "-k", key) == EXIT_ERROR
    assert "ya existe" in capsys.readouterr().err
    assert run("check", root, "-b", baseline, "-k", key) == EXIT_CHANGES  # la de antes sigue ahí
    assert run("init", root, "-b", baseline, "-k", key, "--force") == EXIT_OK


def test_excludes_are_stored_in_the_baseline(site):
    root, baseline, key = site
    run("init", root, "-b", baseline, "-k", key, "-e", "*.log")
    (root / "app.log").write_text("línea 2\n")  # los logs cambian solos, no deben saltar
    assert run("check", root, "-b", baseline, "-k", key) == EXIT_OK


def test_tampered_baseline_is_detected(site, capsys):
    root, baseline, key = site
    run("init", root, "-b", baseline, "-k", key)
    # El atacante cambia un archivo y "arregla" su hash en la línea base para esconderlo.
    (root / "index.html").write_text("<h1>Hackeado</h1>")
    doc = json.loads(baseline.read_text())
    doc["payload"]["files"]["index.html"]["sha256"] = scan(root).records["index.html"].sha256
    baseline.write_text(json.dumps(doc))
    assert run("check", root, "-b", baseline, "-k", key) == EXIT_TAMPERED
    assert "ALERTA" in capsys.readouterr().err
    # y tampoco puede "aceptarla" con update
    assert run("update", root, "-b", baseline, "-k", key) == EXIT_TAMPERED


def test_wrong_key_is_detected(site, tmp_path):
    root, baseline, key = site
    run("init", root, "-b", baseline, "-k", key)
    other = tmp_path / "otra.key"
    other.write_text("f" * 64)
    assert run("check", root, "-b", baseline, "-k", other) == EXIT_TAMPERED


def test_key_from_environment_and_missing_key(site, monkeypatch, capsys):
    root, baseline, _ = site
    monkeypatch.delenv("FIMGUARD_KEY", raising=False)
    assert run("init", root, "-b", baseline) == EXIT_ERROR
    assert "falta la clave" in capsys.readouterr().err
    monkeypatch.setenv("FIMGUARD_KEY", KEY)
    assert run("init", root, "-b", baseline) == EXIT_OK


def test_missing_key_file(site, tmp_path, capsys):
    root, baseline, _ = site
    assert run("init", root, "-b", baseline, "-k", tmp_path / "no-existe.key") == EXIT_ERROR
    assert "no se pudo leer la clave" in capsys.readouterr().err


def test_short_key_is_rejected(tmp_path):
    short = tmp_path / "k"
    short.write_text("1234")
    with pytest.raises(bl.BaselineError, match="corta"):
        bl.load_key(short)


def test_baseline_inside_watched_directory_excludes_itself(site):
    root, _, key = site
    inside = root / "baseline.json"
    run("init", root, "-b", inside, "-k", key)
    run("update", root, "-b", inside, "-k", key)
    assert run("check", root, "-b", inside, "-k", key) == EXIT_OK


def test_corrupt_baseline(site):
    root, baseline, key = site
    baseline.write_text("{no es json")
    assert run("check", root, "-b", baseline, "-k", key) == EXIT_ERROR


def test_checking_another_directory_warns(site, tmp_path, capsys):
    root, baseline, key = site
    run("init", root, "-b", baseline, "-k", key)
    other = tmp_path / "otra"
    other.mkdir()
    run("check", other, "-b", baseline, "-k", key)
    assert "la línea base se hizo sobre" in capsys.readouterr().err


def test_key_inside_watched_directory_warns(site, capsys):
    root, baseline, _ = site
    key = root / "clave.key"
    key.write_text(KEY)
    run("init", root, "-b", baseline, "-k", key)
    assert "la clave está dentro del directorio vigilado" in capsys.readouterr().err


@posix_only
def test_readable_key_warns(site, capsys):
    root, baseline, key = site
    key.chmod(0o644)
    run("init", root, "-b", baseline, "-k", key)
    assert "otros usuarios pueden leer la clave" in capsys.readouterr().err


def test_keygen(tmp_path, capsys):
    assert run("keygen") == EXIT_OK
    assert len(capsys.readouterr().out.strip()) == 64
    out = tmp_path / "nueva.key"
    assert run("keygen", "--out", out) == EXIT_OK
    assert len(out.read_text().strip()) == 64
    assert run("keygen", "--out", out) == EXIT_ERROR  # nunca pisa una clave


@posix_only
def test_keygen_file_is_private(tmp_path):
    out = tmp_path / "nueva.key"
    run("keygen", "--out", out)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


@posix_only
def test_baseline_file_is_private(site):
    root, baseline, key = site
    run("init", root, "-b", baseline, "-k", key)
    assert stat.S_IMODE(baseline.stat().st_mode) == 0o600


@posix_only
def test_file_name_cannot_erase_its_own_line(site, capsys):
    root, baseline, key = site
    run("init", root, "-b", baseline, "-k", key)
    (root / "x.php\r\x1b[1A\x1b[2K").write_text("<?php ?>")
    capsys.readouterr()
    assert run("check", root, "-b", baseline, "-k", key) == EXIT_CHANGES
    out = capsys.readouterr().out
    assert "\x1b[1A" not in out and "\r" not in out
    assert "x.php\\r\\x1b[1A\\x1b[2K" in out


@pytest.mark.skipif(sys.platform != "linux", reason="nombres que no son UTF-8: solo en Linux")
def test_non_utf8_file_name_does_not_crash(site, capsys):
    root, baseline, key = site
    run("init", root, "-b", baseline, "-k", key)
    with open(os.fsencode(root) + b"/\xff\xfe.php", "wb") as fh:
        fh.write(b"<?php ?>")
    capsys.readouterr()
    assert run("check", root, "-b", baseline, "-k", key) == EXIT_CHANGES
    assert ".php" in capsys.readouterr().out
    assert run("check", root, "-b", baseline, "-k", key, "--json") == EXIT_CHANGES
    [change] = json.loads(capsys.readouterr().out)
    assert change["kind"] == "added"


def test_demo_runs(capsys):
    assert run("demo") == EXIT_OK
    out = capsys.readouterr().out
    assert "uploads/avatar.php.jpg" in out and "ALERTA" in out


def test_write_errors_are_reported_not_crashed(site, tmp_path, capsys):
    root, _, key = site
    assert run("keygen", "--out", tmp_path / "no" / "existe.key") == EXIT_ERROR
    (tmp_path / "archivo.txt").write_text("")  # un archivo donde debería haber una carpeta
    assert run("init", root, "-b", tmp_path / "archivo.txt" / "baseline.json", "-k", key) == EXIT_ERROR
    assert "no se pudo guardar" in capsys.readouterr().err
