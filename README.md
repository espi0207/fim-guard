# fim-guard

[![CI](https://github.com/espi0207/fim-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/espi0207/fim-guard/actions/workflows/ci.yml)

Monitor de integridad de archivos (FIM) escrito en Python, sin dependencias. Hace
una "foto" de un directorio (hash SHA-256 de cada archivo, permisos, propietario,
destino de los enlaces simbólicos) y después avisa de cualquier cambio. Además marca
los cambios que tienen mala pinta: un `.php` nuevo en la carpeta de subidas, un
script al que le aparece el bit setuid, un enlace que ahora apunta a `/etc/passwd`...

Es la misma idea que Tripwire o AIDE, pero pequeño, para entender cómo funcionan
por dentro.

## El problema de la línea base

Un FIM compara el estado actual con una línea base guardada. Si esa línea base es un
JSON normal, el mismo atacante que ha cambiado tus archivos puede volver a generarla
(o editar el hash del archivo que ha tocado) y el monitor no vería nada.

fim-guard firma la línea base con HMAC-SHA256. Sin la clave no se puede crear una
firma válida, así que cualquier cambio en la línea base se detecta. La clave se
guarda fuera del servidor vigilado, o al menos donde el usuario de la web no llegue.

## Instalación

Hace falta Python 3.10 o superior. Está pensado para Linux, que es donde lo he probado.

```bash
git clone https://github.com/espi0207/fim-guard.git
cd fim-guard
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Probarlo

```bash
fimguard demo
```

Monta una web de prueba en un directorio temporal, hace la línea base, simula un
ataque, lo detecta, intenta falsificar la línea base y lo detecta también. Al acabar
borra el directorio temporal. El resultado del `check` en medio del ataque:

```text
[*] MODIFICADO  index.html  (53 -> 29 bytes, sha256 cf867f507584... -> 90c71d34f5d5...)
[-] ELIMINADO   robots.txt  (32 bytes)
[*] MODIFICADO  scripts/backup.sh  (44 -> 105 bytes, sha256 bb50d1503439... -> f6428f1d482d..., permisos 0755 -> 4755)
                !! sospechoso: setuid
[*] MODIFICADO  settings.conf  (el enlace apuntaba a config/app.conf y ahora a /etc/passwd)
                !! sospechoso: el enlace apunta fuera del directorio vigilado (/etc/passwd)
[+] AÑADIDO     uploads  (directorio)
[+] AÑADIDO     uploads/.cache\x1b[1A\x1b[2K.php  (8 bytes)
                !! sospechoso: script web nuevo (posible webshell)
                !! sospechoso: el nombre tiene caracteres invisibles o de control (truco para esconderlo)
[+] AÑADIDO     uploads/avatar.php.jpg  (48 bytes)
                !! sospechoso: script web nuevo (posible webshell)

7 cambios, 4 sospechosos
```

## Uso

```bash
fimguard keygen --out ~/fimguard.key                       # clave aleatoria de 256 bits
fimguard init /var/www -b baseline.json -k ~/fimguard.key -e "*.log" -e cache
fimguard check /var/www -b baseline.json -k ~/fimguard.key
fimguard update /var/www -b baseline.json -k ~/fimguard.key  # después de un despliegue
```

- `-e` excluye archivos o carpetas por patrón (logs, cachés, lo que cambie solo). Los
  patrones se guardan dentro de la línea base firmada, así que nadie puede añadir
  exclusiones después para esconder algo.
- `update` imprime la lista de cambios que acepta, para que quede constancia.
- `init` no sobrescribe una línea base que ya existe, salvo con `--force`.
- La clave también se puede pasar en la variable de entorno `FIMGUARD_KEY`.
- `check --json` saca los cambios en JSON.

Códigos de salida de `check`:

| Código | Qué significa |
|---|---|
| 0 | Todo igual que en la línea base |
| 1 | Hay cambios |
| 2 | Error (falta la clave, el directorio no existe...) |
| 3 | La firma no cuadra: han tocado la línea base o la clave no es la buena |

Con eso se puede lanzar desde cron y avisar solo si algo no va bien:

```cron
*/15 * * * * /opt/fim-guard/.venv/bin/fimguard check /var/www -b /root/baseline.json -k /root/fimguard.key > /root/fimguard.txt 2>&1 || /usr/local/bin/avisar.sh /root/fimguard.txt
```

## Qué marca como sospechoso

| Cambio | Por qué |
|---|---|
| Archivo nuevo con extensión que el servidor puede ejecutar (`.php`, `.phtml`, `.phar`, `.jsp`, `.aspx`...) | Es lo que deja un atacante que consigue subir archivos: una webshell. Se miran todas las extensiones, porque `foto.php.jpg` se ejecuta como PHP con algunas configuraciones de Apache |
| Aparece el bit setuid o setgid | Un ejecutable setuid se ejecuta con los permisos de su dueño: es una forma clásica de escalar privilegios |
| Archivo o carpeta que pasa a ser escribible por cualquiera | Cualquier usuario de la máquina podría cambiarlo |
| Un archivo que pasa a ser ejecutable | Un script que antes no se podía ejecutar y ahora sí |
| Enlace simbólico que apunta fuera del directorio | Un enlace a `/etc/passwd` dentro de la web puede acabar sirviéndolo |
| Nombre con caracteres de control o invisibles | Se usan para esconder archivos (ver abajo) |

Si un archivo no se puede leer, sale como `ILEGIBLE` y no como eliminado: el archivo
sigue ahí aunque no se pueda comprobar.

## Algunas decisiones

- **La firma se comprueba antes de mirar el contenido** de la línea base, y con
  `hmac.compare_digest`, que tarda lo mismo acierte o falle (una comparación normal
  deja adivinar la firma midiendo tiempos). El JSON se firma en forma canónica (claves
  ordenadas, sin espacios) para que siempre dé los mismos bytes.
- **No se siguen los enlaces simbólicos.** Se guardan como enlaces con su destino. Si
  se siguieran, un enlace plantado haría leer archivos de fuera del directorio, o un
  bucle dejaría el escaneo colgado.
- **Nada de trampas al abrir los archivos.** Entre que se mira un archivo y se abre,
  alguien podría cambiarlo por un enlace o por una FIFO (y el programa se quedaría
  esperando para siempre). Se abre con `O_NOFOLLOW | O_NONBLOCK` y se comprueba que lo
  abierto es el mismo archivo regular que se vio antes.
- **Los nombres de archivo no se imprimen tal cual.** En Linux un nombre puede llevar
  cualquier byte salvo `/`. Un atacante puede llamar a su webshell `x.php` seguido de
  secuencias ANSI que suben el cursor y borran la línea, y el aviso desaparecería de
  la terminal. Antes de sacarlos se escapan los caracteres de control, los invisibles
  (como el U+202E, que da la vuelta al texto) y los bytes que no son UTF-8, que además
  hacían fallar el `print`.
- **La línea base se escribe de forma atómica** (archivo temporal, `fsync` y
  `os.replace`) y con permisos 600. Si está dentro del directorio vigilado, se excluye
  a sí misma. `keygen` nunca sobrescribe una clave que ya existe.

```text
fimguard/
├── scanner.py   recorre el directorio: SHA-256, permisos, propietario, enlaces
├── baseline.py  guarda y carga la línea base firmada
├── diff.py      compara y decide qué es sospechoso
├── demo.py      el ataque de mentira de `fimguard demo`
└── __main__.py  línea de comandos
```

## Limitaciones

- La clave tiene que estar donde se ejecuta `check`. Si alguien consigue root en esa
  máquina puede leerla y volver a firmar lo que quiera. Lo más seguro es comprobar
  desde otra máquina, con el directorio montado en solo lectura.
- Alguien que tenga una línea base antigua firmada con la misma clave (de una copia de
  seguridad, por ejemplo) podría ponerla en lugar de la actual. La firma sería válida;
  por eso `check` enseña la fecha de la línea base.
- Es una foto cada cierto tiempo, no vigilancia continua. Si algo se cambia y se deja
  como estaba entre dos comprobaciones, no se ve. Para eso están inotify o auditd.
- Solo mira el contenido, los permisos y el propietario. No guarda fechas, atributos
  extendidos ni ACLs.

## Pruebas

```bash
pip install -e ".[dev]"
pytest
```

Entre otras cosas, las pruebas hacen de atacante: cambian un archivo y "arreglan" su
hash en la línea base, cuelan una FIFO en lugar de un archivo, o crean archivos con
nombres llenos de secuencias de escape.

## Licencia

[MIT](LICENSE)
