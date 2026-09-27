"""Línea base firmada con HMAC-SHA256.

Sin firma, un atacante que cambia archivos también podría regenerar la línea base y el
monitor no vería nada. Con HMAC hace falta la clave para crear una línea base válida, y
la clave se guarda fuera del sistema vigilado (otra máquina, un gestor de secretos, un USB).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .scanner import FileRecord

FORMAT_VERSION = 1
MIN_KEY_BYTES = 16


class BaselineError(Exception):
    """La línea base no se puede leer o no tiene el formato esperado."""


class BaselineTampered(BaselineError):
    """La firma no coincide: la línea base se ha modificado o la clave es otra."""


def generate_key() -> str:
    return secrets.token_hex(32)


def load_key(key_file: Path | None, env: dict[str, str] | None = None) -> bytes:
    env = os.environ if env is None else env
    if key_file is not None:
        try:
            raw = key_file.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise BaselineError(f"no se pudo leer la clave {key_file}: {exc.strerror}") from exc
    elif env.get("FIMGUARD_KEY"):
        raw = env["FIMGUARD_KEY"].strip()
    else:
        raise BaselineError("falta la clave: usa --key-file o la variable de entorno FIMGUARD_KEY")
    key = raw.encode("utf-8")
    if len(key) < MIN_KEY_BYTES:
        raise BaselineError(f"la clave es demasiado corta (mínimo {MIN_KEY_BYTES} caracteres), genera una con keygen")
    return key


def _canonical(payload: dict) -> bytes:
    # Siempre los mismos bytes para los mismos datos (claves ordenadas, sin espacios), si no
    # la firma cambiaría según cómo se haya escrito el JSON.
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sign(payload: dict, key: bytes) -> str:
    return hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()


def build_payload(root: Path, records: dict[str, FileRecord], excludes: list[str]) -> dict:
    return {
        "version": FORMAT_VERSION,
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "root": str(root.resolve()),
        "algorithm": "sha256",
        "excludes": excludes,
        "files": {path: rec.to_dict() for path, rec in sorted(records.items())},
    }


def save(path: Path, payload: dict, key: bytes) -> None:
    document = {"payload": payload, "hmac_sha256": sign(payload, key)}
    # Se escribe en un temporal y luego se renombra: si el proceso muere a mitad, la línea
    # base anterior sigue entera. mkstemp ya crea el archivo con permisos 600.
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".fimguard-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(document, fh, indent=1, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def load(path: Path, key: bytes) -> dict:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
        payload, signature = document["payload"], document["hmac_sha256"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise BaselineError(f"no se pudo leer la línea base {path}: {exc}") from exc
    # compare_digest tarda lo mismo acierte o falle, así no se puede adivinar la firma
    # byte a byte midiendo tiempos. La firma se comprueba antes de mirar nada del contenido.
    if not isinstance(signature, str) or not hmac.compare_digest(sign(payload, key), signature):
        raise BaselineTampered(
            "la firma HMAC de la línea base no es válida: alguien la ha modificado o la clave no es la misma"
        )
    if payload.get("version") != FORMAT_VERSION:
        raise BaselineError(f"versión de línea base no soportada: {payload.get('version')}")
    return payload


def records_from_payload(payload: dict) -> dict[str, FileRecord]:
    try:
        return {path: FileRecord.from_dict(data) for path, data in payload["files"].items()}
    except (KeyError, TypeError, AttributeError) as exc:
        raise BaselineError(f"la línea base no tiene el formato esperado: {exc}") from exc
