"""Recorre un directorio y guarda la huella de cada entrada: tipo, permisos, propietario y SHA-256."""

from __future__ import annotations

import errno
import fnmatch
import hashlib
import os
import stat
import struct
from dataclasses import asdict, dataclass
from pathlib import Path

from .content import MAX_INSPECT, markers, should_inspect

CHUNK = 1024 * 1024
ROOT = "."  # nombre con el que se guarda la propia carpeta vigilada

# No existen en Windows; ahí valen 0 y simplemente no se usan.
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
O_BINARY = getattr(os, "O_BINARY", 0)
_getxattr = getattr(os, "getxattr", None)  # solo en Linux

# Lo que no es archivo, carpeta ni enlace. No tienen contenido que comparar, pero que aparezca
# uno en una carpeta de archivos es raro: un socket es un programa escuchando ahí.
SPECIAL_KINDS = {
    stat.S_IFIFO: "fifo",
    stat.S_IFSOCK: "socket",
    stat.S_IFCHR: "device",
    stat.S_IFBLK: "device",
}

# Capacidades de Linux, por su número (linux/capability.h). Son trozos del poder de root que se
# le pueden dar a un programa con setcap: cap_setuid o cap_sys_admin equivalen a un setuid de
# root, pero no se ven con ls -l.
CAPABILITIES = (
    "chown dac_override dac_read_search fowner fsetid kill setgid setuid setpcap linux_immutable "
    "net_bind_service net_broadcast net_admin net_raw ipc_lock ipc_owner sys_module sys_rawio sys_chroot "
    "sys_ptrace sys_pacct sys_admin sys_boot sys_nice sys_resource sys_time sys_tty_config mknod lease "
    "audit_write audit_control setfcap mac_override mac_admin syslog wake_alarm block_suspend audit_read "
    "perfmon bpf checkpoint_restore"
).split()


def capability_names(raw: bytes) -> tuple[str, ...]:
    """Nombres de las capacidades que da el atributo security.capability (struct vfs_cap_data)."""
    if len(raw) < 12:
        return ()
    words = struct.unpack(f"<{len(raw) // 4}I", raw[: len(raw) // 4 * 4])
    # palabra 0: versión y flags; después, pares (permitidas, heredables) de 32 bits
    bits = words[1] | words[2] | ((words[3] | words[4]) << 32 if len(words) >= 5 else 0)
    return tuple(f"cap_{CAPABILITIES[i]}" if i < len(CAPABILITIES) else f"cap_{i}" for i in range(64) if bits >> i & 1)


def _capabilities(path: Path) -> tuple[str, ...] | None:
    if _getxattr is None:
        return None
    try:
        return capability_names(_getxattr(path, "security.capability", follow_symlinks=False)) or None
    except OSError:
        return None  # lo normal: el archivo no tiene (ENODATA) o el disco no admite atributos


@dataclass(frozen=True)
class FileRecord:
    kind: str  # "file", "dir" o "symlink"
    mode: int  # permisos, incluidos setuid/setgid/sticky
    uid: int
    gid: int
    size: int = 0
    sha256: str | None = None  # solo archivos
    target: str | None = None  # solo enlaces simbólicos
    # Scripts web y .htaccess: el código sospechoso que llevan dentro (ver content.py).
    # None si no se ha mirado o no tienen nada, así las líneas base de antes siguen igual.
    markers: tuple[str, ...] | None = None
    # Capacidades de Linux que tiene el archivo (setcap). None si no tiene ninguna.
    caps: tuple[str, ...] | None = None

    def to_dict(self) -> dict:
        data = {k: v for k, v in asdict(self).items() if v is not None}
        for name in ("markers", "caps"):
            if name in data:
                data[name] = list(data[name])
        return data

    @classmethod
    def from_dict(cls, data: dict) -> FileRecord:
        data = dict(data)
        for name in ("markers", "caps"):
            if data.get(name) is not None:
                data[name] = tuple(data[name])
        return cls(**data)


@dataclass
class ScanResult:
    records: dict[str, FileRecord]
    errors: dict[str, str]  # ruta -> motivo por el que no se pudo leer


def is_excluded(rel_path: str, patterns: list[str]) -> bool:
    """Un patrón vale para la ruta o para el nombre en cualquier carpeta («*.log»). Si empieza
    por «/», solo para esa ruta exacta desde la raíz y sin bajar a subcarpetas («/baseline.json»)."""
    name = rel_path.rsplit("/", 1)[-1]
    for p in patterns:
        if p.startswith("/"):
            anchored = p[1:]
            if anchored.count("/") == rel_path.count("/") and fnmatch.fnmatch(rel_path, anchored):
                return True
        elif fnmatch.fnmatch(rel_path, p) or fnmatch.fnmatch(name, p):
            return True
    return False


def _hash_file(path: Path, expected: os.stat_result, inspect: bool = False) -> tuple[str, int, tuple[str, ...]]:
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
        kept: list[bytes] | None = [] if inspect and st.st_size <= MAX_INSPECT else None
        while chunk := fh.read(CHUNK):
            digest.update(chunk)
            if kept is not None:
                kept.append(chunk)
        # Si ha cambiado mientras se leía, la huella no es de ningún estado real del archivo
        # (media versión vieja, media nueva): mejor decir que no se pudo leer que guardarla.
        after = os.fstat(fh.fileno())
        if (after.st_size, after.st_mtime_ns, after.st_mode) != (st.st_size, st.st_mtime_ns, st.st_mode):
            raise OSError(errno.EAGAIN, "el archivo ha cambiado mientras se leía")
    return digest.hexdigest(), st.st_size, markers(b"".join(kept), path.name) if kept is not None else ()


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
        sha256, size, found = _hash_file(path, st, inspect=should_inspect(path.name))
        return FileRecord(
            "file", mode, st.st_uid, st.st_gid, size, sha256=sha256, markers=found or None, caps=_capabilities(path)
        )
    if kind := SPECIAL_KINDS.get(stat.S_IFMT(st.st_mode)):
        return FileRecord(kind, mode, st.st_uid, st.st_gid)
    return None


def scan(root: Path, excludes: list[str] | None = None) -> ScanResult:
    """Escanea `root` sin seguir enlaces simbólicos.

    Un enlace se guarda como enlace, con su destino. Si se siguiera, un atacante podría
    plantar uno que hiciera leer archivos de fuera del directorio, o crear un bucle.
    """
    excludes = excludes or []
    root = root.resolve()
    result = ScanResult(records={}, errors={})
    # La propia carpeta también se vigila, como ".": con un chmod 777 o un cambio de dueño
    # sobre ella cualquiera podría crear o borrar archivos dentro.
    try:
        result.records[ROOT] = _record(root)
    except OSError as exc:
        result.errors[ROOT] = exc.strerror or str(exc)

    def on_error(exc: OSError) -> None:
        rel = os.path.relpath(exc.filename, root).replace(os.sep, "/") if exc.filename else ROOT
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
