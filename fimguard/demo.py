"""`fimguard demo`: un ataque inventado a una web, de principio a fin, en un directorio temporal.

No toca nada fuera de ese directorio y lo borra al acabar.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

from . import baseline as bl
from .ansi import paint
from .diff import compare
from .scanner import scan

# Nombre con secuencias ANSI: "subir una línea" y "borrar la línea". Impreso tal cual en
# una terminal, la línea que avisa de este archivo desaparecería.
HIDDEN_NAME = "uploads/.cache\x1b[1A\x1b[2K.php"


def _step(n: int, text: str) -> None:
    print()
    print(paint(f"{n}. {text}", "bold", "cyan"))
    time.sleep(0.2)


def _build_site(root: Path) -> None:
    files = {
        "index.html": "<h1>Tienda Retro</h1><p>Cartuchos de segunda mano</p>",
        "robots.txt": "User-agent: *\nDisallow: /admin/\n",
        "css/style.css": "body { font-family: monospace; }",
        "admin/panel.php": "<?php require 'auth.php'; ?>",
        "config/app.conf": "db_host=localhost\n",
        "scripts/backup.sh": "#!/bin/sh\ntar czf /backups/web.tgz /var/www\n",
    }
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    if os.name != "nt":
        os.chmod(root / "scripts/backup.sh", 0o755)
        os.symlink("config/app.conf", root / "settings.conf")


def _attack(root: Path) -> None:
    (root / "index.html").write_text("<h1>HACKED BY 0xDEADBEEF</h1>", encoding="utf-8")
    (root / "uploads").mkdir()
    (root / "uploads/avatar.php.jpg").write_text("<?php /* webshell de mentira, no hace nada */ ?>", encoding="utf-8")
    (root / "robots.txt").unlink()
    with open(root / "scripts/backup.sh", "a", encoding="utf-8") as fh:
        fh.write("# línea añadida por el atacante (de mentira, no hace nada)\n")
    if os.name != "nt":
        os.chmod(root / "scripts/backup.sh", 0o4755)  # setuid: se ejecutaría como su dueño
        (root / "settings.conf").unlink()
        os.symlink("/etc/passwd", root / "settings.conf")
        (root / HIDDEN_NAME).write_text("<?php ?>", encoding="utf-8")


def run_demo() -> int:
    from .__main__ import print_changes

    print(paint("fim-guard: demostración con un ataque simulado", "bold"))
    with tempfile.TemporaryDirectory(prefix="fimguard-demo-") as tmp:
        site, key = Path(tmp) / "www", bl.generate_key().encode()
        baseline_path = Path(tmp) / "baseline.json"
        _build_site(site)

        _step(1, "Una web recién desplegada")
        for rel, rec in sorted(scan(site).records.items()):
            print(f"   {rel}{'/' if rec.kind == 'dir' else ''}")

        _step(2, "Se toma la línea base y se firma con HMAC-SHA256")
        records = scan(site).records
        bl.save(baseline_path, bl.build_payload(site, records, []), key)
        print(f"   {len(records)} entradas guardadas en {baseline_path.name}")
        print(
            paint("   (en un servidor de verdad la clave estaría en otra máquina; aquí solo vive en memoria)", "gray")
        )

        _step(3, "Entra un atacante")
        _attack(site)
        print("   cambia la portada, sube una webshell con doble extensión, borra robots.txt,")
        print("   modifica un script y le pone setuid, redirige un enlace a /etc/passwd y deja")
        print("   otra webshell con un nombre que intenta borrarse de la pantalla")

        _step(4, "fimguard check")
        payload = bl.load(baseline_path, key)
        current = scan(site)
        changes = compare(bl.records_from_payload(payload), current.records, current.errors, payload["root"])
        print_changes(changes)
        suspicious = sum(1 for c in changes if c.suspicious)
        print(paint(f"\n{len(changes)} cambios, {suspicious} sospechosos", "bold"))

        _step(5, "El atacante edita la línea base para tapar la portada cambiada")
        doc = json.loads(baseline_path.read_text(encoding="utf-8"))
        doc["payload"]["files"]["index.html"]["sha256"] = current.records["index.html"].sha256
        baseline_path.write_text(json.dumps(doc), encoding="utf-8")
        try:
            bl.load(baseline_path, key)
        except bl.BaselineTampered as exc:
            print(paint(f"   ALERTA: {exc}", "bold", "bright_red"))
            print(paint("   sin la clave no puede volver a firmarla", "gray"))

    print()
    print(paint("Directorio temporal borrado.", "green"))
    return 0
