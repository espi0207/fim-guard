"""Recorre un directorio y guarda la huella de cada entrada: tipo, permisos, propietario y SHA-256."""

from __future__ import annotations

import errno
import fnmatch
import hashlib
import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path

CHUNK = 1024 * 1024

# No existen en Windows; ahí valen 0 y simplemente no se usan.
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
O_BINARY = getattr(os, "O_BINARY", 0)


@dataclass(frozen=True)
class FileRecord:
    kind: str  # "file", "dir" o "symlink"
    mode: int  # permisos, incluidos setuid/setgid/sticky
    uid: int
    gid: int
    size: int = 0
    sha256: str | None = None  # solo archivos
    target: str | None = None  # solo enlaces simbólicos

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}

    @classmethod
    def from_dict(cls, data: dict) -> FileRecord:
        return cls(**data)


@dataclass
class ScanResult:
    records: dict[str, FileRecord]
    errors: dict[str, str]  # ruta -> motivo por el que no se pudo leer


def is_excluded(rel_path: str, patterns: list[str]) -> bool:
    name = rel_path.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(rel_path, p) or fnmatch.fnmatch(name, p) for p in patterns)


def _hash_file(path: Path, expected: os.stat_result) -> tuple[str, int]:
    """SHA-256 de un archivo regular, sin caer en trampas.

    Entre el lstat() y el open() alguien podría cambiar el archivo por un enlace (a
    /etc/shadow, por ejemplo) o por una FIFO, y el open() se quedaría esperando para
    siempre. Por eso se abre sin seguir enlaces y sin bloquear, y después se comprueba
    que lo que se ha abierto es el mismo archivo regular que se vio con lstat().
    """
    fd = os.open(path, os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_BINARY)
    with os.fdopen(fd, "rb") as fh:
        st = os.fstat(fh.fileno())
        if not stat.S_ISREG(st.st_mode) or (st.st_dev, st.st_ino) != (expected.st_dev, expected.st_ino):
            raise OSError(errno.EAGAIN, "el archivo ha cambiado mientras se leía")
        digest = hashlib.sha256()
        while chunk := fh.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest(), st.st_size


def _record(path: Path) -> FileRecord | None:
    st = path.lstat()
    mode = stat.S_IMODE(st.st_mode)
    if stat.S_ISLNK(st.st_mode):
        # Los permisos de un enlace no significan nada (en Linux siempre son 0777). Se guarda 0
        # para que no parezca un archivo escribible por cualquiera.
        return FileRecord("symlink", 0, st.st_uid, st.st_gid, target=os.readlink(path))
    if stat.S_ISDIR(st.st_mode):
        return FileRecord("dir", mode, st.st_uid, st.st_gid)
    if stat.S_ISREG(st.st_mode):
        sha256, size = _hash_file(path, st)
        return FileRecord("file", mode, st.st_uid, st.st_gid, size, sha256=sha256)
    return None  # sockets, FIFOs y dispositivos no se vigilan


def scan(root: Path, excludes: list[str] | None = None) -> ScanResult:
    """Escanea `root` sin seguir enlaces simbólicos.

    Un enlace se guarda como enlace, con su destino. Si se siguiera, un atacante podría
    plantar uno que hiciera leer archivos de fuera del directorio, o crear un bucle.
    """
    excludes = excludes or []
    root = root.resolve()
    result = ScanResult(records={}, errors={})

    def on_error(exc: OSError) -> None:
        rel = os.path.relpath(exc.filename, root).replace(os.sep, "/") if exc.filename else "?"
        result.errors[rel] = exc.strerror or str(exc)

    for dirpath, dirnames, filenames in os.walk(root, onerror=on_error):
        rel_dir = os.path.relpath(dirpath, root).replace(os.sep, "/")
        rel_dir = "" if rel_dir == "." else rel_dir + "/"
        # Los directorios excluidos se quitan de la lista para que os.walk no entre en ellos.
        dirnames[:] = sorted(d for d in dirnames if not is_excluded(rel_dir + d, excludes))
        files = sorted(f for f in filenames if not is_excluded(rel_dir + f, excludes))
        # En dirnames también vienen los enlaces a directorios (os.walk no entra en ellos).
        for name in dirnames + files:
            rel = rel_dir + name
            try:
                record = _record(Path(dirpath, name))
            except OSError as exc:
                result.errors[rel] = exc.strerror or str(exc)
                continue
            if record is not None:
                result.records[rel] = record
    return result
