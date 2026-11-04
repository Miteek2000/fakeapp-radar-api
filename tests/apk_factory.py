"""Fábrica de APKs de prueba INOFENSIVOS.

Arma un archivo .apk mínimo (un ZIP con un AndroidManifest.xml en formato
binario de Android) que solo *declara* permisos. No contiene código, así que
no hace nada: sirve para probar el analizador sin usar malware real.

Uso desde la terminal:
    python -m tests.apk_factory banco-falso.apk READ_SMS BIND_ACCESSIBILITY_SERVICE CAMERA
"""
import struct
import sys
import zipfile

NS_ANDROID = "http://schemas.android.com/apk/res/android"
TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
NO_REF = 0xFFFFFFFF


def _pool(strings: list[str]) -> bytes:
    blobs = []
    for s in strings:
        raw = s.encode("utf-16-le")
        blobs.append(struct.pack("<H", len(s)) + raw + b"\x00\x00")
    offsets, pos = [], 0
    for b in blobs:
        offsets.append(pos)
        pos += len(b)
    data = b"".join(blobs)
    if len(data) % 4:
        data += b"\x00" * (4 - len(data) % 4)
    header_size = 28
    strings_start = header_size + 4 * len(strings)
    size = strings_start + len(data)
    head = struct.pack("<HHIIIIII", 0x0001, header_size, size, len(strings), 0, 0, strings_start, 0)
    return head + b"".join(struct.pack("<I", o) for o in offsets) + data


def _chunk16(ctype: int, body: bytes) -> bytes:
    # cabecera de 16 bytes: tipo, tamaño de cabecera, tamaño total, línea, comentario
    return struct.pack("<HHIII", ctype, 16, 16 + len(body), 1, NO_REF) + body


def _start(name_idx: int, attrs: list[tuple]) -> bytes:
    # attrs: (ns_idx|None, name_idx, tipo, valor_idx_o_entero)
    body = struct.pack("<IIHHHHHH", NO_REF, name_idx, 20, 20, len(attrs), 0, 0, 0)
    for ns, name, vtype, value in attrs:
        raw = value if vtype == TYPE_STRING else NO_REF
        body += struct.pack("<IIIHBBI", NO_REF if ns is None else ns, name, raw, 8, 0, vtype, value)
    return _chunk16(0x0102, body)


def _end(name_idx: int) -> bytes:
    return _chunk16(0x0103, struct.pack("<II", NO_REF, name_idx))


def build_manifest(package: str, app_label: str, version: str, permissions: list[str]) -> bytes:
    strings: list[str] = []

    def s(text: str) -> int:
        if text not in strings:
            strings.append(text)
        return strings.index(text)

    ns_prefix, ns_uri = s("android"), s(NS_ANDROID)
    n_manifest, n_package = s("manifest"), s("package")
    n_name, n_label = s("name"), s("label")
    n_vname, n_minsdk, n_target = s("versionName"), s("minSdkVersion"), s("targetSdkVersion")
    n_uses_sdk, n_perm, n_app = s("uses-sdk"), s("uses-permission"), s("application")

    body = _chunk16(0x0100, struct.pack("<II", ns_prefix, ns_uri))
    body += _start(n_manifest, [
        (None, n_package, TYPE_STRING, s(package)),
        (ns_uri, n_vname, TYPE_STRING, s(version)),
    ])
    body += _start(n_uses_sdk, [
        (ns_uri, n_minsdk, TYPE_INT_DEC, 21),
        (ns_uri, n_target, TYPE_INT_DEC, 34),
    ])
    body += _end(n_uses_sdk)
    for p in permissions:
        body += _start(n_perm, [(ns_uri, n_name, TYPE_STRING, s(p))])
        body += _end(n_perm)
    body += _start(n_app, [(ns_uri, n_label, TYPE_STRING, s(app_label))])
    body += _end(n_app)
    body += _end(n_manifest)
    body += _chunk16(0x0101, struct.pack("<II", ns_prefix, ns_uri))

    pool = _pool(strings)
    total = 8 + len(pool) + len(body)
    return struct.pack("<HHI", 0x0003, 8, total) + pool + body


def make_apk(path, package="com.ejemplo.prueba", app_label="App de prueba",
             version="1.0", permissions=()):
    """Crea un APK de prueba en `path`. Los permisos sin punto se completan
    con el prefijo android.permission."""
    full = [p if "." in p else f"android.permission.{p}" for p in permissions]
    manifest = build_manifest(package, app_label, version, full)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("AndroidManifest.xml", manifest)
    return path


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Uso: python -m tests.apk_factory salida.apk [PERMISO ...]")
    make_apk(sys.argv[1], permissions=sys.argv[2:])
    print(f"Creado {sys.argv[1]} con {len(sys.argv) - 2} permiso(s)")
