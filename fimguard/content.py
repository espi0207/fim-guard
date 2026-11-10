"""Lo que hay dentro de los scripts web: el código típico de una webshell.

El ataque más habitual en una web no es subir un archivo nuevo (eso ya lo marca la
extensión), sino meter unas líneas en un PHP que ya estaba: el hash cambia igual que con
una actualización normal. Por eso, de los scripts que el servidor puede ejecutar (y de
los .htaccess y .user.ini, que deciden qué se ejecuta), se guarda en la línea base qué
marcas tiene, y se avisa cuando aparece una que antes no estaba.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath

# Extensiones que un servidor web puede ejecutar. Se miran todas las del nombre porque con
# algunas configuraciones de Apache "foto.php.jpg" se ejecuta como PHP.
WEB_SCRIPTS = {
    ".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml", ".phar", ".pht",
    ".jsp", ".jspx", ".jspf", ".jsw", ".jsv", ".cfm", ".cfml",
    # .asa, .cer y .cdx: IIS los ejecuta como ASP, y por eso se usan para saltarse filtros de subida
    ".asp", ".aspx", ".ashx", ".asmx", ".ascx", ".asa", ".cer", ".cdx", ".cgi", ".pl", ".shtml",
}  # fmt: skip
# Archivos de configuración que cambian lo que ejecuta el servidor.
SERVER_CONFIG = {".htaccess", ".user.ini", "php.ini"}
MAX_INSPECT = 2 * 1024 * 1024  # los scripts de verdad son mucho más pequeños

_SHELL_FUNCS = r"(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)"
_REQUEST = r"\$_(?:get|post|request|cookie|server|files)"

# marca → (expresión regular sobre el texto en minúsculas, explicación)
MARKERS: dict[str, tuple[re.Pattern, str]] = {
    "eval-ofuscado": (
        re.compile(
            r"(?:eval|assert)\s*\(\s*@?\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|"
            r"rawurldecode|hex2bin|strrev)\s*\("
        ),
        "ejecuta código escondido (eval de base64, gzinflate o str_rot13)",
    ),
    "ejecuta-peticion": (
        re.compile(_SHELL_FUNCS + r"\s*\(\s*@?\s*(?:stripslashes\s*\(\s*)?" + _REQUEST),
        "ejecuta lo que llega en la petición (system($_GET[…]) o parecido)",
    ),
    "funcion-variable": (
        re.compile(_REQUEST + r"\s*\[[^\]]{0,40}\]\s*\("),
        "llama a la función que elija el visitante ($_REQUEST['f'](…))",
    ),
    "comillas-invertidas": (
        # <?=`$_GET[0]`?>: en PHP, lo que va entre comillas invertidas se ejecuta en la terminal
        re.compile(r"`[\w\s/.-]{0,30}\{?\s*" + _REQUEST + r"\b"),
        "ejecuta en la terminal lo que llega en la petición (comillas invertidas)",
    ),
    "llamada-indirecta": (
        # la función a la que se llama viene en la petición: call_user_func($_REQUEST['f'], ...)
        re.compile(
            r"(?:call_user_func(?:_array)?|array_map)\s*\(\s*"
            + _REQUEST
            + r"|(?:array_filter|array_walk|usort|uasort|uksort)\s*\([^,()]{1,60},\s*"
            + _REQUEST
            + r"|create_function\s*\([^)]{0,60}"
            + _REQUEST
        ),
        "llama a la función que elija el visitante (call_user_func, array_map, create_function)",
    ),
    "incluye-peticion": (
        re.compile(r"(?:include|require)(?:_once)?\s*\(?\s*" + _REQUEST),
        "carga como código el archivo que diga el visitante (include($_GET[…]))",
    ),
    "ejecuta-cuerpo": (
        re.compile(r"(?:eval|assert)\s*\(\s*@?\s*file_get_contents\s*\(\s*['\"]php://input"),
        "ejecuta como código lo que se le mande (eval de php://input)",
    ),
    "asp-eval": (
        re.compile(r"(?:eval|execute)\s*\(?\s*request\s*[(.]"),
        "ejecuta lo que llega en la petición (eval request, en ASP)",
    ),
    "preg-e": (
        # el patrón entre comillas, su delimitador y unos modificadores que incluyen la e
        re.compile(r"preg_replace\s*\(\s*(['\"])([^a-z0-9\s\\])[^'\"\n]*\2[imsxuadj]*e[imsxuadj]*\1\s*,"),
        "preg_replace con /e, que ejecuta el resultado como código",
    ),
    "java-exec": (
        re.compile(r"runtime\s*\.\s*getruntime\s*\(\s*\)\s*\.\s*exec\s*\("),
        "ejecuta órdenes del sistema desde Java (Runtime.exec)",
    ),
    "dotnet-exec": (
        re.compile(r"process\s*\.\s*start\s*\(|processstartinfo"),
        "ejecuta órdenes del sistema desde .NET (Process.Start)",
    ),
    "blob-ofuscado": (
        re.compile(r"(?:base64_decode|gzinflate|str_rot13)\s*\(\s*['\"][a-z0-9+/=\\\s]{400,}"),
        "lleva un bloque largo de código ofuscado",
    ),
    "config-ejecuta": (
        # que imágenes o texto se ejecuten como PHP, o un PHP que se carga antes de cada página
        re.compile(
            r"(?:addtype|addhandler)\s+\S*php\S*\s+[^\n]*\.(?:jpe?g|png|gif|ico|txt|svg|webp|bmp|css|js)\b|"
            r"sethandler\s+\S*php|auto_(?:prepend|append)_file(?:[ \t]*=[ \t]*|[ \t]+)[\"']?[^\s\"';=]|"
            # CGI donde no lo había, o volver a encender PHP en una carpeta donde estaba apagado
            r"addhandler\s+cgi-script|options\s[^\n]*\+execcgi|php_(?:admin_)?flag\s+engine\s+(?:on|1)\b"
        ),
        "hace que imágenes o texto se ejecuten como PHP, o carga un PHP antes de cada página",
    ),
}
WEBSHELL = {"eval-ofuscado", "ejecuta-peticion", "funcion-variable", "preg-e", "java-exec", "dotnet-exec",
            "blob-ofuscado", "comillas-invertidas", "llamada-indirecta", "incluye-peticion", "ejecuta-cuerpo",
            "asp-eval"}  # fmt: skip


def should_inspect(name: str) -> bool:
    name = PurePosixPath(name).name
    return name.lower() in SERVER_CONFIG or bool(WEB_SCRIPTS & {s.lower() for s in PurePosixPath(name).suffixes})


def markers(data: bytes, name: str = "") -> tuple[str, ...]:
    """Las marcas de un script (las de webshell) o de un .htaccess / .user.ini (las de configuración)."""
    text = data.decode("latin-1").lower()
    config = PurePosixPath(name).name.lower() in SERVER_CONFIG
    wanted = {"config-ejecuta"} if config else WEBSHELL
    return tuple(sorted(m for m in wanted if MARKERS[m][0].search(text)))


def describe(marker: str) -> str:
    label = MARKERS[marker][1] if marker in MARKERS else marker
    if marker in WEBSHELL:
        return f"código típico de webshell: {label}"
    return f"configuración peligrosa del servidor web: {label}"


# Archivos del sistema donde un cambio merece mirarse aunque sea pequeño: así se queda un
# atacante (una cuenta, una clave SSH, una tarea programada) o se esconde (ld.so.preload).
SENSITIVE: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(^|/)(passwd|shadow|group|gshadow)$"), "cuentas del sistema"),
    (re.compile(r"(^|/)sudoers$|(^|/)sudoers\.d/"), "quién puede usar sudo"),
    (re.compile(r"(^|/)\.ssh/authorized_keys2?$"), "claves SSH con las que se puede entrar"),
    (re.compile(r"(^|/)(crontab|anacrontab)$|(^|/)cron\.(d|hourly|daily|weekly|monthly)/.|(^|/)spool/cron/."),
     "tarea programada (una forma de quedarse en la máquina)"),
    (re.compile(r"(^|/)systemd/(system|user)/.+\.(service|timer|socket|path)$"), "servicio que arranca solo"),
    (re.compile(r"(^|/)ld\.so\.preload$"), "carga una librería en todos los programas (técnica de rootkits)"),
    (re.compile(r"(^|/)(\.bashrc|\.bash_profile|\.profile|\.zshrc|bash\.bashrc|profile|rc\.local)$|(^|/)profile\.d/."),
     "se ejecuta al abrir una sesión"),
    (re.compile(r"(^|/)ssh/sshd_config$|(^|/)sshd_config\.d/."), "configuración del servidor SSH"),
    (re.compile(r"(^|/)pam\.d/."), "cómo se comprueban las contraseñas (PAM)"),
]  # fmt: skip


def sensitive(path: str) -> str | None:
    for regex, label in SENSITIVE:
        if regex.search(path):
            return label
    return None
