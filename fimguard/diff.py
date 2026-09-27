"""Compara la línea base con el estado actual y marca los cambios sospechosos."""

from __future__ import annotations

import posixpath
import stat
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from .scanner import FileRecord

try:
    import grp
    import pwd
except ImportError:  # Windows
    grp = pwd = None

# Extensiones que un servidor web puede ejecutar. Se miran todas las del nombre porque con
# algunas configuraciones de Apache "foto.php.jpg" se ejecuta como PHP.
WEB_SCRIPTS = {
    ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".phar", ".pht",
    ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".cgi", ".pl", ".shtml",
}  # fmt: skip


@dataclass
class Change:
    kind: str  # added | removed | modified | permissions | owner | type | unreadable
    path: str
    detail: str = ""
    suspicious: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "path": self.path, "detail": self.detail, "suspicious": self.suspicious}


def owner_name(uid: int, gid: int) -> str:
    """ "root:www-data" si se pueden resolver los nombres, si no "0:33"."""
    try:
        user = pwd.getpwuid(uid).pw_name
    except (AttributeError, KeyError):
        user = str(uid)
    try:
        group = grp.getgrgid(gid).gr_name
    except (AttributeError, KeyError):
        group = str(gid)
    return f"{user}:{group}"


def _risky_bits(rec: FileRecord) -> set[str]:
    risks = set()
    if rec.mode & stat.S_ISUID:
        risks.add("setuid")
    if rec.mode & stat.S_ISGID and rec.kind != "dir":  # setgid en carpetas compartidas es normal
        risks.add("setgid")
    if rec.mode & stat.S_IWOTH:
        risks.add("escribible por cualquiera")
    return risks


def link_escapes(link_path: str, target: str, root: str | None) -> bool:
    """¿El enlace apunta fuera del directorio vigilado?

    Se calcula sobre el texto de la ruta, sin tocar el disco: "a/b/enlace -> ../c" se
    queda dentro, "enlace -> ../../etc" no. No se tienen en cuenta otros enlaces que
    hubiera por el camino.
    """
    target = target.replace("\\", "/")
    if target.startswith("/") or target[1:2] == ":":  # absoluta (o C:/ en Windows)
        if root is None:
            return True
        root = root.replace("\\", "/").rstrip("/")
        resolved = posixpath.normpath(target)
        return not (resolved == root or resolved.startswith(root + "/"))
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(link_path), target))
    return resolved == ".." or resolved.startswith("../")


def _suspicious(old: FileRecord | None, new: FileRecord, path: str, root: str | None) -> list[str]:
    """Riesgos que aparecen con el cambio. Los que ya estaban en la línea base no se repiten."""
    notes = sorted(_risky_bits(new) - (_risky_bits(old) if old else set()))
    if new.kind == "file" and new.mode & 0o111 and not (old and old.mode & 0o111):
        notes.append("nuevo ejecutable")
    if old is None:
        name = PurePosixPath(path).name
        if new.kind == "file" and WEB_SCRIPTS & {s.lower() for s in PurePosixPath(name).suffixes}:
            notes.append("script web nuevo (posible webshell)")
        if not name.isprintable():
            notes.append("el nombre tiene caracteres invisibles o de control (truco para esconderlo)")
    if new.kind == "symlink" and new.target and not (old and old.target == new.target):
        if link_escapes(path, new.target, root):
            notes.append(f"el enlace apunta fuera del directorio vigilado ({new.target})")
    return notes


def _describe(rec: FileRecord) -> str:
    if rec.kind == "symlink":
        return f"-> {rec.target}"
    if rec.kind == "dir":
        return "directorio"
    return f"{rec.size} bytes"


def _under_unreadable_dir(path: str, errors: dict[str, str]) -> bool:
    return any(path.startswith(d + "/") for d in errors)


def compare(
    baseline: dict[str, FileRecord],
    current: dict[str, FileRecord],
    errors: dict[str, str] | None = None,
    root: str | None = None,
) -> list[Change]:
    """Lista de cambios entre dos escaneos.

    `errors` son las rutas que no se pudieron leer en el escaneo actual: salen como
    "ilegible" y no como "eliminado", que sería mentira (el archivo sigue ahí, pero no
    se puede comprobar). `root` es el directorio original de la línea base, para saber
    si un enlace con ruta absoluta se sale de él.
    """
    errors = errors or {}
    changes: list[Change] = []
    for path in sorted(baseline.keys() | current.keys() | errors.keys()):
        old, new = baseline.get(path), current.get(path)
        if path in errors:
            changes.append(Change("unreadable", path, errors[path]))
        elif new is None and _under_unreadable_dir(path, errors):
            continue  # su carpeta no se pudo leer y ya sale como ilegible
        elif old is None:
            changes.append(Change("added", path, _describe(new), _suspicious(None, new, path, root)))
        elif new is None:
            changes.append(Change("removed", path, _describe(old)))
        elif old.kind != new.kind:
            changes.append(Change("type", path, f"{old.kind} -> {new.kind}", _suspicious(old, new, path, root)))
        else:
            change = _compare_same_kind(old, new, path)
            if change:
                change.suspicious = _suspicious(old, new, path, root)
                changes.append(change)
    return changes


def _compare_same_kind(old: FileRecord, new: FileRecord, path: str) -> Change | None:
    parts = []
    kind = None
    if old.sha256 != new.sha256:
        parts.append(f"{old.size} -> {new.size} bytes, sha256 {old.sha256[:12]}... -> {new.sha256[:12]}...")
        kind = "modified"
    if old.target != new.target:
        parts.append(f"el enlace apuntaba a {old.target} y ahora a {new.target}")
        kind = "modified"
    if old.mode != new.mode:
        parts.append(f"permisos {old.mode:04o} -> {new.mode:04o}")
        kind = kind or "permissions"
    if (old.uid, old.gid) != (new.uid, new.gid):
        parts.append(f"propietario {owner_name(old.uid, old.gid)} -> {owner_name(new.uid, new.gid)}")
        kind = kind or "owner"
    if kind is None:
        return None
    return Change(kind, path, ", ".join(parts))
