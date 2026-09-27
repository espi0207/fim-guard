"""Línea de comandos: fimguard keygen | init | check | update | demo."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from . import baseline as bl
from .ansi import clean, paint
from .diff import Change, compare
from .scanner import scan

EXIT_OK, EXIT_CHANGES, EXIT_ERROR, EXIT_TAMPERED = 0, 1, 2, 3

LABELS = {
    "added": ("[+] AÑADIDO", "green"),
    "removed": ("[-] ELIMINADO", "red"),
    "modified": ("[*] MODIFICADO", "yellow"),
    "permissions": ("[~] PERMISOS", "magenta"),
    "owner": ("[~] PROPIETARIO", "magenta"),
    "type": ("[!] TIPO", "bright_red"),
    "unreadable": ("[?] ILEGIBLE", "bright_red"),
}
WIDTH = 16


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="fimguard", description="Monitor de integridad de archivos con línea base firmada")
    sub = p.add_subparsers(dest="command", required=True)

    keygen = sub.add_parser("keygen", help="genera una clave aleatoria de 256 bits")
    keygen.add_argument("--out", type=Path, help="guardar la clave en este archivo (con permisos 600)")
    sub.add_parser("demo", help="simula un ataque a una web en un directorio temporal y lo detecta")

    for name, text in [
        ("init", "crea la línea base de un directorio"),
        ("check", "compara el directorio con su línea base"),
        ("update", "acepta el estado actual como nueva línea base"),
    ]:
        cmd = sub.add_parser(name, help=text)
        cmd.add_argument("directory", type=Path)
        cmd.add_argument("--baseline", "-b", type=Path, required=True, help="archivo JSON de la línea base")
        cmd.add_argument("--key-file", "-k", type=Path, help="archivo con la clave (o la variable FIMGUARD_KEY)")
        if name == "init":
            cmd.add_argument("--exclude", "-e", action="append", default=[], help="patrón a ignorar (repetible)")
            cmd.add_argument("--force", action="store_true", help="sobrescribir una línea base que ya existe")
        if name == "check":
            cmd.add_argument("--json", action="store_true", help="salida en JSON")
    return p


def _auto_excludes(directory: Path, baseline_path: Path) -> list[str]:
    """Si la línea base está dentro del directorio vigilado, se excluye a sí misma."""
    try:
        rel = baseline_path.resolve().relative_to(directory.resolve()).as_posix()
    except ValueError:
        return []
    return [rel, ".fimguard-*.tmp"]


def _warn(text: str) -> None:
    print(paint(f"aviso: {text}", "yellow", stream=sys.stderr), file=sys.stderr)


def _check_key_location(key_file: Path | None, directory: Path) -> None:
    if key_file is None:
        return
    if key_file.resolve().is_relative_to(directory.resolve()):
        _warn("la clave está dentro del directorio vigilado; quien pueda tocar los archivos podrá leerla")
    if os.name != "nt" and key_file.exists() and stat.S_IMODE(key_file.stat().st_mode) & 0o077:
        _warn(f"otros usuarios pueden leer la clave {key_file}; ponle permisos 600 (chmod 600)")


def print_changes(changes: list[Change], out=None) -> None:
    out = out or sys.stdout
    for c in changes:
        label, color = LABELS[c.kind]
        line = f"{paint(label.ljust(WIDTH), 'bold', color)}{clean(c.path)}"
        if c.detail:
            line += paint(f"  ({clean(c.detail)})", "gray")
        print(line, file=out)
        for note in c.suspicious:
            print(paint(f"{' ' * WIDTH}!! sospechoso: {clean(note)}", "bold", "bright_red"), file=out)


def _summary(records) -> str:
    dirs = sum(r.kind == "dir" for r in records.values())
    files = len(records) - dirs
    return f"{files} archivo{'' if files == 1 else 's'} y {dirs} directorio{'' if dirs == 1 else 's'}"


def _save(args, records, excludes, key) -> bool:
    try:
        bl.save(args.baseline, bl.build_payload(args.directory, records, excludes), key)
    except OSError as exc:
        print(f"error: no se pudo guardar la línea base en {args.baseline}: {exc.strerror}", file=sys.stderr)
        return False
    return True


def keygen(out: Path | None) -> int:
    key = bl.generate_key()
    if out is None:
        print(key)
        return EXIT_OK
    try:
        # exist_ok=False: si ya hay una clave ahí no la piso, que perderla deja inservibles
        # todas las líneas base firmadas con ella.
        out.touch(mode=0o600, exist_ok=False)
    except FileExistsError:
        print(f"error: {out} ya existe y no voy a sobrescribir una clave", file=sys.stderr)
        return EXIT_ERROR
    except OSError as exc:
        print(f"error: no se pudo crear {out}: {exc.strerror}", file=sys.stderr)
        return EXIT_ERROR
    out.write_text(key + "\n", encoding="utf-8")
    print(f"clave guardada en {out}. Guárdala fuera de la máquina que vigilas.", file=sys.stderr)
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "demo":
        from .demo import run_demo

        return run_demo()
    if args.command == "keygen":
        return keygen(args.out)

    if not args.directory.is_dir():
        print(f"error: {args.directory} no es un directorio", file=sys.stderr)
        return EXIT_ERROR
    if args.command == "init" and args.baseline.exists() and not args.force:
        print(
            f"error: {args.baseline} ya existe. Usa update para aceptar los cambios, o --force para empezar de cero",
            file=sys.stderr,
        )
        return EXIT_ERROR

    try:
        key = bl.load_key(args.key_file)
        if args.command == "init":
            excludes = sorted(set(args.exclude + _auto_excludes(args.directory, args.baseline)))
        else:
            previous = bl.load(args.baseline, key)
            excludes = previous.get("excludes", [])
            baseline_records = bl.records_from_payload(previous)
    except bl.BaselineTampered as exc:
        print(paint(f"ALERTA: {exc}", "bold", "bright_red", stream=sys.stderr), file=sys.stderr)
        return EXIT_TAMPERED
    except bl.BaselineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    _check_key_location(args.key_file, args.directory)

    root = str(args.directory.resolve())
    if args.command != "init" and previous.get("root") != root:
        # No es un error: puede que se esté comprobando desde otra máquina con el disco montado.
        _warn(f"la línea base se hizo sobre {previous['root']} y estás comprobando {root}")

    result = scan(args.directory, excludes)

    if args.command == "init":
        for path, err in result.errors.items():
            _warn(f"no se pudo leer {clean(path)} ({err}), no entra en la línea base")
        if not _save(args, result.records, excludes, key):
            return EXIT_ERROR
        print(f"línea base creada con {_summary(result.records)} en {args.baseline}")
        return EXIT_OK

    changes = compare(baseline_records, result.records, result.errors, previous.get("root"))

    if args.command == "update":
        if changes:
            print_changes(changes)
            print()
        if not _save(args, result.records, excludes, key):
            return EXIT_ERROR
        print(f"línea base actualizada ({len(changes)} cambio(s) aceptados): {_summary(result.records)}")
        return EXIT_OK

    if args.json:
        # ensure_ascii: un nombre de archivo que no es UTF-8 válido haría fallar el print.
        print(json.dumps([c.to_dict() for c in changes], indent=2, ensure_ascii=True))
    elif changes:
        print_changes(changes)
        suspicious = sum(1 for c in changes if c.suspicious)
        print(
            paint(
                f"\n{len(changes)} cambio(s), {suspicious} sospechoso(s). Línea base del {previous['created']}", "bold"
            )
        )
    else:
        print(
            paint(
                f"Sin cambios: {_summary(result.records)} igual que en la línea base del {previous['created']}", "green"
            )
        )
    return EXIT_CHANGES if changes else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
