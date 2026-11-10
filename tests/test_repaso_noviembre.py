"""Repaso del 10 de noviembre: lo que entraba en la carpeta sin dejar rastro y webshells mínimas."""

import os
import socket
import struct

import pytest

from fimguard import scanner
from fimguard.__main__ import main
from fimguard.content import markers, should_inspect
from fimguard.diff import compare
from fimguard.scanner import FileRecord, scan

KEY = "clave-de-prueba-0123456789abcdef"


def run(*args):
    return main([*args])


@pytest.fixture
def web(tmp_path, monkeypatch):
    monkeypatch.setenv("FIMGUARD_KEY", KEY)
    root = tmp_path / "www"
    (root / "uploads").mkdir(parents=True)
    (root / "index.php").write_text("<?php echo 'hola'; ?>\n")
    (root / "uploads" / ".htaccess").write_text("php_flag engine off\n")
    return root


# Tuberías, sockets y dispositivos


@pytest.mark.skipif(os.name == "nt", reason="FIFOs y sockets de Unix")
def test_new_fifo_and_socket_are_reported(web, tmp_path, capsys):
    baseline = tmp_path / "base.json"
    assert run("init", str(web), "-b", str(baseline)) == 0
    os.mkfifo(web / "uploads" / "tubo")
    with socket.socket(socket.AF_UNIX) as sock:
        sock.bind(str(web / "uploads" / "puerta.sock"))
        assert run("check", str(web), "-b", str(baseline)) == 1
    out = capsys.readouterr().out
    assert "uploads/tubo" in out and "uploads/puerta.sock" in out
    assert "tubería" in out and "socket" in out


# Capacidades


def caps_xattr(*bits: int) -> bytes:
    permitted = sum(1 << b for b in bits)
    return struct.pack("<IIIII", 0x02000002, permitted & 0xFFFFFFFF, 0, permitted >> 32, 0)


@pytest.fixture
def with_caps(monkeypatch):
    """Hace como si los archivos llamados "herramienta" tuvieran las capacidades que se le digan."""
    current: dict[str, bytes] = {}

    def fake_getxattr(path, name, follow_symlinks=True):
        if name == "security.capability" and os.path.basename(str(path)) in current:
            return current[os.path.basename(str(path))]
        raise OSError(61, "No data available")

    monkeypatch.setattr(scanner, "_getxattr", fake_getxattr)
    return current


def test_binary_that_gains_capabilities_is_suspicious(web, tmp_path, capsys, with_caps):
    tool = web / "herramienta"
    tool.write_bytes(b"\x7fELF...")
    baseline = tmp_path / "base.json"
    assert run("init", str(web), "-b", str(baseline)) == 0
    with_caps["herramienta"] = caps_xattr(7, 21)  # setcap cap_setuid,cap_sys_admin+ep herramienta
    assert run("check", str(web), "-b", str(baseline)) == 1
    out = capsys.readouterr().out
    assert "cap_setuid" in out and "cap_sys_admin" in out and "sospechoso" in out


def test_capabilities_already_in_the_baseline_are_not_news(web, tmp_path, capsys, with_caps):
    (web / "herramienta").write_bytes(b"\x7fELF...")
    with_caps["herramienta"] = caps_xattr(13)  # cap_net_raw, como ping
    baseline = tmp_path / "base.json"
    assert run("init", str(web), "-b", str(baseline)) == 0
    assert run("check", str(web), "-b", str(baseline)) == 0


def test_baseline_from_before_capabilities_does_not_cry_wolf(web, tmp_path, capsys, with_caps):
    # Una línea base hecha con la versión anterior no sabe qué capacidades había: no se puede
    # decir que son nuevas. Avisa de que hay que hacer update, y a partir de ahí sí las vigila.
    (web / "herramienta").write_bytes(b"\x7fELF...")
    baseline = tmp_path / "base.json"
    assert run("init", str(web), "-b", str(baseline)) == 0
    import json

    from fimguard import baseline as bl

    document = json.loads(baseline.read_text())
    document["payload"].pop("features")
    bl.save(baseline, document["payload"], KEY.encode())
    with_caps["herramienta"] = caps_xattr(13)
    assert run("check", str(web), "-b", str(baseline)) == 0
    assert "update" in capsys.readouterr().err


# Webshells mínimas y configuración


@pytest.mark.parametrize(
    "code",
    [
        "<?=`$_GET[0]`?>",
        "<?php echo `{$_POST['c']}`; ?>",
        "<?php call_user_func($_REQUEST['f'], $_REQUEST['a']); ?>",
        "<?php array_map($_GET['f'], [$_GET['a']]); ?>",
        "<?php include($_GET['p']); ?>",
        "<?php require_once $_REQUEST['modulo']; ?>",
        "<?php eval(file_get_contents('php://input')); ?>",
        "<?php $f = create_function('', $_POST['x']); $f(); ?>",
    ],
)
def test_tiny_php_webshells_are_marked(code):
    assert markers(code.encode(), "x.php"), code


def test_classic_asp_one_liner_is_marked():
    assert markers(b'<%eval request("cmd")%>', "x.asp")
    assert markers(b'<% Execute(Request.Form("c")) %>', "x.asp")


def test_ordinary_php_is_not_marked():
    for code in (
        "<?php include __DIR__ . '/config.php'; require_once 'vendor/autoload.php'; ?>",
        "<?php $id = (int) $_GET['id']; echo htmlspecialchars($_POST['nombre']); ?>",
        "<?php $r = array_map('trim', $_POST['lineas']); usort($lista, 'comparar'); ?>",
        "<?php echo `date`; $x = call_user_func('strtoupper', $nombre); ?>",
        '<?php $sql = "SELECT `id`, `nombre` FROM `t` WHERE id = " . (int) $_GET[\'id\'] . " AND `x` = 1"; ?>',
    ):
        assert markers(code.encode(), "x.php") == (), code


@pytest.mark.parametrize(
    "line",
    [
        "php_value auto_prepend_file /var/www/uploads/logo.png",
        "AddHandler cgi-script .jpg",
        "Options +ExecCGI",
        "php_flag engine on",
    ],
)
def test_htaccess_that_makes_things_run_is_marked(line):
    assert markers(line.encode(), ".htaccess") == ("config-ejecuta",), line


def test_ordinary_htaccess_is_not_marked():
    text = "Options -Indexes\nRewriteEngine On\nRewriteRule ^(.*)$ index.php [L]\nphp_flag engine off\n"
    assert markers(text.encode(), ".htaccess") == ()


def test_more_extensions_that_servers_run():
    for name in ("x.php8", "x.asa", "x.cer", "x.asmx", "x.cfm", "x.jspf", "foto.PHP8.jpg"):
        assert should_inspect(name), name
    assert not should_inspect("certificado.pem") and not should_inspect("notas.txt")


# Borrar lo que protegía


def test_removing_the_htaccess_that_protected_a_folder_is_suspicious():
    old = {
        "uploads/.htaccess": FileRecord("file", 0o644, 0, 0, 20, sha256="a" * 64),
        "nota.txt": FileRecord("file", 0o644, 0, 0, 3, sha256="b" * 64),
    }
    changes = {c.path: c for c in compare(old, {})}
    assert changes["uploads/.htaccess"].suspicious and not changes["nota.txt"].suspicious


def test_scan_still_ignores_nothing(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    assert set(scan(tmp_path).records) == {".", "a.txt"}
