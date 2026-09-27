import hashlib
import os

import pytest

from fimguard import compare, scan
from fimguard import scanner as sc
from fimguard.diff import link_escapes
from fimguard.scanner import FileRecord

posix_only = pytest.mark.skipif(os.name == "nt", reason="permisos, enlaces y FIFOs de POSIX")


@pytest.fixture
def root(tmp_path):
    root = tmp_path / "www"
    (root / "css").mkdir(parents=True)
    (root / "index.html").write_text("<h1>Hola</h1>")
    (root / "css" / "style.css").write_text("body { color: black }")
    (root / "app.log").write_text("línea 1\n")
    return root


def changes_by_path(before, after, **kw):
    return {c.path: c for c in compare(before, after, **kw)}


def test_scan_hashes_files_and_records_dirs(root):
    records = scan(root).records
    assert set(records) == {"index.html", "css", "css/style.css", "app.log"}
    assert records["index.html"].sha256 == hashlib.sha256(b"<h1>Hola</h1>").hexdigest()
    assert records["css"].kind == "dir" and records["css"].sha256 is None


def test_excludes(root):
    assert "app.log" not in scan(root, ["*.log"]).records
    assert not any(p.startswith("css") for p in scan(root, ["css"]).records)


def test_new_directory_is_detected(root):
    before = scan(root).records
    (root / "uploads").mkdir()
    assert [(c.kind, c.path) for c in compare(before, scan(root).records)] == [("added", "uploads")]


@posix_only
def test_world_writable_directory_is_suspicious(root):
    before = scan(root).records
    os.chmod(root / "css", 0o777)
    change = changes_by_path(before, scan(root).records)["css"]
    assert change.kind == "permissions"
    assert change.suspicious == ["escribible por cualquiera"]


def test_owner_change():
    old = {"a.php": FileRecord("file", 0o644, 0, 0, 3, sha256="x")}
    new = {"a.php": FileRecord("file", 0o644, 33, 33, 3, sha256="x")}
    change = compare(old, new)[0]
    assert change.kind == "owner" and "propietario" in change.detail


def test_content_and_permissions_change_together():
    old = {"a.sh": FileRecord("file", 0o644, 0, 0, 3, sha256="aaa")}
    new = {"a.sh": FileRecord("file", 0o755, 0, 0, 4, sha256="bbb")}
    change = compare(old, new)[0]
    assert change.kind == "modified"
    assert "permisos 0644 -> 0755" in change.detail
    assert change.suspicious == ["nuevo ejecutable"]


@posix_only
def test_symlinks_are_recorded_not_followed(root, tmp_path):
    outside = tmp_path / "fuera.txt"
    outside.write_text("fuera del directorio vigilado")
    os.symlink(outside, root / "enlace")
    os.symlink(tmp_path, root / "enlace_dir")
    records = scan(root).records
    assert records["enlace"].kind == "symlink" and records["enlace"].sha256 is None
    assert records["enlace"].target == str(outside)
    assert records["enlace_dir"].kind == "symlink"
    assert not any(p.startswith("enlace_dir/") for p in records)


@posix_only
def test_redirected_symlink_is_modified(root):
    os.symlink("index.html", root / "home")
    before = scan(root).records
    (root / "home").unlink()
    os.symlink("/etc/passwd", root / "home")
    assert [(c.kind, c.path) for c in compare(before, scan(root).records)] == [("modified", "home")]


@posix_only
def test_suspicious_permission_changes(root):
    before = scan(root).records
    os.chmod(root / "index.html", 0o4755)
    os.chmod(root / "css" / "style.css", 0o666)
    changes = changes_by_path(before, scan(root).records)
    assert changes["index.html"].kind == "permissions"
    assert set(changes["index.html"].suspicious) == {"setuid", "nuevo ejecutable"}
    assert changes["css/style.css"].suspicious == ["escribible por cualquiera"]


def test_new_web_script_is_suspicious(root):
    before = scan(root).records
    (root / "css" / "x.php").write_text("<?php ?>")
    (root / "css" / "foto.PHP.jpg").write_text("<?php ?>")  # doble extensión y en mayúsculas
    (root / "notes.txt").write_text("hola")
    (root / "jquery.min.js").write_text("")
    changes = {c.path: c.suspicious for c in compare(before, scan(root).records)}
    assert changes == {
        "css/x.php": ["script web nuevo (posible webshell)"],
        "css/foto.PHP.jpg": ["script web nuevo (posible webshell)"],
        "notes.txt": [],
        "jquery.min.js": [],
    }


@posix_only
def test_invisible_characters_in_name_are_suspicious(root):
    before = scan(root).records
    (root / "logo‮gnp.php").write_text("<?php ?>")  # se ve como "logophp.png"
    [change] = compare(before, scan(root).records)
    assert any("caracteres invisibles" in note for note in change.suspicious)


@pytest.mark.parametrize(
    "link, target, escapes",
    [
        ("ok_link", "css/style.css", False),
        ("a/b/link", "../c/data", False),  # sube una carpeta pero sigue dentro
        ("link", "../../etc/shadow", True),
        ("a/link", "../../x", True),
        ("link", "/var/www/html/img.png", False),  # absoluto pero dentro de la raíz
        ("link", "/etc/passwd", True),
        ("link", "/var/www-evil/x", True),  # empieza igual que la raíz pero no es ella
    ],
)
def test_link_escapes(link, target, escapes):
    assert link_escapes(link, target, "/var/www") is escapes


@posix_only
def test_symlink_escaping_root_is_suspicious(root):
    os.symlink("css/style.css", root / "ok_link")
    os.symlink("../../etc/shadow", root / "bad_link")
    changes = {c.path: c.suspicious for c in compare({}, scan(root).records, root=str(root))}
    assert changes["ok_link"] == []
    assert changes["bad_link"] == ["el enlace apunta fuera del directorio vigilado (../../etc/shadow)"]


def test_unreadable_file_is_not_reported_as_removed(root, monkeypatch):
    before = scan(root).records
    real_hash = sc._hash_file

    def no_permission(path, expected):
        if path.name == "index.html":
            raise PermissionError(13, "Permission denied")
        return real_hash(path, expected)

    monkeypatch.setattr(sc, "_hash_file", no_permission)
    result = scan(root)
    assert result.errors == {"index.html": "Permission denied"}
    changes = compare(before, result.records, result.errors)
    assert [(c.kind, c.path) for c in changes] == [("unreadable", "index.html")]


def test_files_inside_an_unreadable_dir_are_not_removed():
    before = {
        "css": FileRecord("dir", 0o755, 0, 0),
        "css/style.css": FileRecord("file", 0o644, 0, 0, 3, sha256="x"),
    }
    now = {"css": FileRecord("dir", 0o755, 0, 0)}  # no se pudo listar su contenido
    changes = compare(before, now, {"css": "Permission denied"})
    assert [(c.kind, c.path) for c in changes] == [("unreadable", "css")]


@posix_only
def test_hash_refuses_a_fifo_swapped_in(tmp_path):
    # Simula la carrera: se vio un archivo normal, pero al abrirlo ya es una FIFO.
    regular = tmp_path / "normal.txt"
    regular.write_text("x")
    fifo = tmp_path / "trampa"
    os.mkfifo(fifo)
    with pytest.raises(OSError):
        sc._hash_file(fifo, regular.lstat())  # sin O_NONBLOCK esto se quedaría colgado


@posix_only
def test_hash_does_not_follow_a_symlink_swapped_in(tmp_path):
    secret = tmp_path / "secreto"
    secret.write_text("no me leas")
    link = tmp_path / "enlace"
    os.symlink(secret, link)
    with pytest.raises(OSError):
        sc._hash_file(link, secret.lstat())


@posix_only
def test_fifos_and_sockets_are_ignored(root):
    os.mkfifo(root / "tuberia")
    assert "tuberia" not in scan(root).records
