"""Noviembre de 2026: lo que hay dentro de los scripts web y los archivos sensibles."""

import pytest

from fimguard import compare, scan
from fimguard.baseline import build_payload, records_from_payload
from fimguard.scanner import FileRecord


@pytest.fixture
def web(tmp_path):
    root = tmp_path / "www"
    root.mkdir()
    (root / "index.php").write_text("<?php echo 'Hola'; ?>\n")
    return root


def suspicious_of(root, change_files: dict[str, str]):
    before = scan(root).records
    for name, text in change_files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    return {c.path: c.suspicious for c in compare(before, scan(root).records)}


@pytest.mark.parametrize(
    "code",
    [
        "<?php @eval(base64_decode($_POST['x'])); ?>",
        "<?php system($_GET['cmd']); ?>",
        "<?php $f = $_REQUEST['f']; $_REQUEST['f']($_REQUEST['a']); ?>",
        "<?php eval(gzinflate(str_rot13(base64_decode('...')))); ?>",
        "<?php assert($_POST['a']); ?>",
        "<?php preg_replace('/.*/e', $_POST['c'], ''); ?>",
    ],
)
def test_code_injected_into_an_existing_php_is_flagged(web, code):
    # El ataque de siempre: no se sube un archivo nuevo, se mete el código en uno que ya estaba.
    notes = suspicious_of(web, {"index.php": "<?php echo 'Hola'; ?>\n" + code})["index.php"]
    assert any("webshell" in n for n in notes), notes


def test_jsp_and_aspx_shells(web):
    found = suspicious_of(
        web,
        {
            "x.jsp": '<% Runtime.getRuntime().exec(request.getParameter("c")); %>',
            "y.aspx": '<% System.Diagnostics.Process.Start("cmd.exe", Request["c"]); %>',
        },
    )
    assert any("webshell" in n for n in found["x.jsp"]) and any("webshell" in n for n in found["y.aspx"])


def test_normal_php_changes_are_not_flagged(web):
    notes = suspicious_of(web, {"index.php": "<?php echo htmlspecialchars($_GET['q'] ?? ''); ?>\n"})["index.php"]
    assert notes == []


def test_code_already_in_the_baseline_is_not_repeated(web):
    (web / "index.php").write_text("<?php system($_GET['cmd']); ?>")
    notes = suspicious_of(web, {"index.php": "<?php system($_GET['cmd']); echo 1; ?>"})["index.php"]
    assert not any("webshell" in n for n in notes)


def test_htaccess_that_runs_images_as_php(web):
    notes = suspicious_of(web, {"uploads/.htaccess": "AddType application/x-httpd-php .jpg\n"})["uploads/.htaccess"]
    assert any("ejecute" in n for n in notes), notes


def test_user_ini_auto_prepend(web):
    notes = suspicious_of(web, {".user.ini": "auto_prepend_file=/tmp/x.php\n"})[".user.ini"]
    assert any("ejecute" in n for n in notes)


@pytest.mark.parametrize(
    ("path", "label"),
    [
        ("sudoers.d/90-extra", "sudo"),
        ("root/.ssh/authorized_keys", "SSH"),
        ("cron.d/actualizar", "programada"),
        ("systemd/system/update.service", "servicio"),
        ("ld.so.preload", "rootkit"),
        ("profile.d/x.sh", "sesión"),
        ("shadow", "cuentas"),
    ],
)
def test_sensitive_system_files(tmp_path, path, label):
    root = tmp_path / "etc"
    root.mkdir()
    notes = suspicious_of(root, {path: "x\n"})[path]
    assert any(label in n for n in notes), notes


def test_markers_survive_the_baseline_and_old_baselines_still_load(web):
    (web / "s.php").write_text("<?php system($_GET['c']); ?>")
    records = scan(web).records
    assert records["s.php"].markers
    payload = build_payload(web, records, [])
    again = records_from_payload(payload)
    assert again["s.php"] == records["s.php"]
    old = {"kind": "file", "mode": 0o644, "uid": 0, "gid": 0, "size": 3, "sha256": "ab"}
    assert FileRecord.from_dict(old).markers is None
    assert "markers" not in records["index.php"].to_dict()  # sin marcas no cambia el formato


@pytest.mark.parametrize(
    "code",
    [
        "<?php $this->addHandler($name, new Action()); ?>",  # un método que se llama así
        "<?php $s = preg_replace('/\\s+/', ' ', $s); $t = preg_replace(\"/e/\", 'x', $t); ?>",
    ],
)
def test_normal_php_is_not_a_webshell(web, code):
    notes = suspicious_of(web, {"index.php": code})["index.php"]
    assert notes == [], notes


def test_default_php_ini_and_normal_htaccess_are_fine(web):
    found = suspicious_of(
        web,
        {
            "php.ini": "auto_prepend_file =\nauto_append_file =\n",
            ".htaccess": "AddHandler application/x-httpd-php74 .php\nRewriteEngine On\n",
        },
    )
    assert not any("ejecute" in n for n in found["php.ini"] + found[".htaccess"])


def test_preg_replace_with_e_modifier(web):
    notes = suspicious_of(web, {"index.php": "<?php preg_replace('/.*/e', $_POST['c'], ''); ?>"})["index.php"]
    assert any("preg_replace" in n for n in notes)
