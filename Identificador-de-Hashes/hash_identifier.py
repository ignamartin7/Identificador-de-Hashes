"""
©AngelaMos | 2026
hash_identifier.py

Identifica el tipo probable de un hash a partir de tres señales:
prefijo, longitud y charset (el conjunto de caracteres usado)

Cuando alguien te pasa una cadena como "5f4dcc3b5aa765d61d8327deb882cf99"
no hay ningún encabezado que diga "esto es un MD5". Lo único que
tenemos son pistas indirectas:

  1. Prefijo   — muchos formatos "modernos" SÍ se identifican solos,
                 porque incrustan un marcador literal al principio:
                 bcrypt siempre empieza con "$2a$", "$2b$" o "$2y$";
                 Argon2id siempre empieza con "$argon2id$"; MySQL 4.1+
                 antepone un asterisco "*"; un JWT siempre empieza con
                 "eyJ" (es el Base64 de '{"'). Si detectamos uno de
                 estos marcadores, la identificación es prácticamente
                 inequívoca

  2. Longitud  — los algoritmos de resumen "clásicos" (MD5, SHA-1,
                 SHA-256...) no llevan ningún marcador: son solo dígitos
                 hexadecimales. Pero cada algoritmo produce SIEMPRE la
                 misma cantidad de caracteres (MD5 → 32, SHA-1 → 40,
                 SHA-256 → 64...), así que la longitud exacta reduce
                 mucho las opciones

  3. Charset   — el alfabeto usado también filtra candidatos. Un hash
                 hexadecimal solo usa [0-9a-f]. Un hash de estilo
                 "crypt" de Unix usa un Base64 propio con "./0-9A-Za-z".
                 Un JWT usa Base64-URL (con "-" y "_" en vez de "+" y
                 "/", y sin relleno "=")

El problema es que la longitud y el charset por sí solos NO bastan
para muchos algoritmos: MD5, NTLM y MD4 producen los tres 32 caracteres
hexadecimales. Es matemáticamente imposible distinguirlos sin más
contexto (¿de qué sistema salió?, ¿qué longitud tenía la contraseña
original?, etc.). Por eso este programa no da una única respuesta:
da una lista de candidatos ordenados por confianza

────────────────────────────────────────────────────────────────────
Los tres niveles de confianza
────────────────────────────────────────────────────────────────────
  alta   Formato con marcador estructural propio (prefijo "$...$",
         "{...}", "*", separadores, etc.). La identificación es
         prácticamente segura
  media  Formato reconocible por longitud/charset que en esta tabla
         no comparte esa combinación exacta con ningún otro (p. ej.
         el crypt(3) clásico de Unix, de 13 caracteres)
  baja   Solo longitud + charset, y esa combinación es compartida por
         varios algoritmos conocidos (p. ej. cualquier cadena de 32
         caracteres hexadecimales podría ser MD5, MD4 o NTLM)

────────────────────────────────────────────────────────────────────
Lo que este script NO hace
────────────────────────────────────────────────────────────────────
  - No intenta romper, descifrar ni fuerza-brutear ningún hash
  - No garantiza el algoritmo exacto en los casos de "baja" confianza,
    solo reduce las posibilidades: la confirmación final depende del
    contexto (de qué sistema vino el dato)
  - No decodifica ni valida el CONTENIDO de formatos como JWT, solo
    reconoce su forma

────────────────────────────────────────────────────────────────────
Qué expone este archivo
────────────────────────────────────────────────────────────────────
  HashSignature     — una firma conocida (patrón, confianza, notas)
  HashMatch         — el resultado de comparar un valor contra una firma
  SIGNATURES        — la tabla completa de firmas conocidas
  identify_hash()   — función pura: cadena -> lista de HashMatch
  detect_charset()  — clasifica el alfabeto usado en la cadena
  detect_prefix()   — detecta un marcador de formato conocido, si hay
  main()            — punto de entrada de la CLI (`hashid-mini`)
"""

# Librería estándar: parsea las banderas de la línea de comandos
# (--list, el valor a identificar, etc.) en un objeto ordenado.
import argparse
# Librería estándar: expresiones regulares. Cada firma de la tabla es,
# en el fondo, un patrón que describe "prefijo + longitud + charset"
# de una sola vez.
import re
# Librería estándar: para leer stdin y para salir con un código de
# salida específico (útil en scripts / CI).
import sys
# Librería estándar: convierte una clase en un "objeto de valor"
# inmutable sin escribir __init__ a mano.
from dataclasses import dataclass
# Librería estándar: fija un valor a un conjunto cerrado de strings.
# Mypy avisa si escribimos "Alta" en vez de "alta" por error.
from typing import Literal

# Terceros (rich): impresión con colores, tablas y paneles en terminal.
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# =============================================================================
# Nivel de confianza — tres valores posibles, ver docstring del módulo
# =============================================================================

Confidence = Literal["alta", "media", "baja"]

# Orden en el que se muestran los resultados: alta primero
_CONFIDENCE_ORDER: dict[Confidence, int] = {"alta": 0, "media": 1, "baja": 2}

# Color asociado a cada nivel, usado solo por la capa de presentación
_CONFIDENCE_COLORS: dict[Confidence, str] = {
    "alta": "bright_green",
    "media": "yellow",
    "baja": "cyan",
}


# =============================================================================
# Generadores de ejemplos "de relleno" — SOLO para ilustrar la forma
# =============================================================================
# Para algoritmos poco comunes (Tiger, HAVAL, GOST, Whirlpool...) no
# vale la pena traer una librería extra solo para mostrar un ejemplo.
# Estas funciones generan una cadena SINTÉTICA con la longitud y el
# charset correctos, para que el usuario vea la FORMA del hash. Se
# marcan explícitamente como "valor ilustrativo" en su descripción —
# nunca se presentan como un hash real de ningún texto


def _hex_placeholder(length: int) -> str:
    """Cadena hexadecimal sintética de longitud exacta (solo forma)."""
    base = "0123456789abcdef"
    return (base * (length // len(base) + 1))[:length]


def _crypt64_placeholder(length: int) -> str:
    """Cadena en el alfabeto Base64 de estilo crypt(3): ./0-9A-Za-z."""
    base = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return (base * (length // len(base) + 1))[:length]


# =============================================================================
# HashSignature — una firma conocida en nuestra base de datos
# =============================================================================


@dataclass(frozen=True, slots=True)
class HashSignature:
    """
    Descripción de un formato de hash conocido

    Fields
    ------
    name
        Nombre del algoritmo o formato (p. ej. "MD5", "bcrypt")
    pattern
        Expresión regular evaluada con `re.fullmatch` contra la cadena
        completa. Codifica a la vez el prefijo, la longitud y el
        charset esperados
    confidence
        Qué tan única es esta firma. Ver docstring del módulo
    description
        Una frase explicando de dónde suele venir este formato
    example
        Un valor de muestra que SÍ cumple `pattern` (verificado por
        los tests). Cuando no proviene de un cálculo real está
        marcado como "(ilustrativo)" en la descripción
    reference
        Referencia técnica opcional útil para herramientas externas,
        p. ej. el modo de Hashcat o el nombre de formato de John the
        Ripper. Es solo metadata de identificación, no una guía para
        atacar nada
    """

    name: str
    pattern: str
    confidence: Confidence
    description: str
    example: str
    reference: str | None = None


# =============================================================================
# La tabla de firmas — única fuente de verdad
# =============================================================================
# Agregar un formato nuevo es el único cambio necesario para ampliar
# el identificador: toda la lógica de abajo simplemente recorre esta
# lista en tiempo de ejecución

SIGNATURES: list[HashSignature] = [
    # -------------------------------------------------------------------
    # Grupo de 8 caracteres hexadecimales — checksums, no hashes
    # criptográficos. Comparten longitud y charset entre sí
    # -------------------------------------------------------------------
    HashSignature(
        name="CRC32",
        pattern=r"^[0-9a-fA-F]{8}$",
        confidence="baja",
        description=(
            "Checksum de 32 bits, NO criptográfico. Común en nombres de "
            "archivo, ZIP, y verificación de integridad simple"
        ),
        example="35c246d5",
        reference="No es un hash de contraseñas; no aplica a Hashcat/John",
    ),
    HashSignature(
        name="Adler32",
        pattern=r"^[0-9a-fA-F]{8}$",
        confidence="baja",
        description=(
            "Checksum de 32 bits usado por zlib, más rápido pero más "
            "débil que CRC32. Misma longitud y charset que CRC32"
        ),
        example="0f910374",
        reference="No es un hash de contraseñas",
    ),
    HashSignature(
        name="CRC32B",
        pattern=r"^[0-9a-fA-F]{8}$",
        confidence="baja",
        description=(
            "Variante de CRC32 usada por PHP (crc32()). Indistinguible "
            "de CRC32 solo por forma"
        ),
        example=_hex_placeholder(8),
        reference="No es un hash de contraseñas",
    ),
    # -------------------------------------------------------------------
    # Grupo de 16 caracteres hexadecimales
    # -------------------------------------------------------------------
    HashSignature(
        name="MySQL 3.23/4.0 (antiguo)",
        pattern=r"^[0-9a-fA-F]{16}$",
        confidence="baja",
        description=(
            "Función PASSWORD() de MySQL anterior a 4.1. Extremadamente "
            "débil, sin sal. Reemplazada por el formato con prefijo '*'"
        ),
        example="5d2e19393cc5ef67",
        reference="Hashcat -m 200 · John: mysql",
    ),
    HashSignature(
        name="Half MD5",
        pattern=r"^[0-9a-fA-F]{16}$",
        confidence="baja",
        description=(
            "Primeros 16 caracteres de un MD5 completo. Usado por algún "
            "software legado para ahorrar espacio en la base de datos"
        ),
        example="5f4dcc3b5aa765d6",
        reference="Hashcat -m 5100",
    ),
    # -------------------------------------------------------------------
    # Grupo de 32 caracteres hexadecimales — el más ambiguo de todos
    # -------------------------------------------------------------------
    HashSignature(
        name="MD5",
        pattern=r"^[0-9a-fA-F]{32}$",
        confidence="baja",
        description="Resumen MD5 (128 bits). Roto criptográficamente, muy común en sistemas legados",
        example="5f4dcc3b5aa765d61d8327deb882cf99",
        reference="Hashcat -m 0 · John: raw-md5",
    ),
    HashSignature(
        name="MD4",
        pattern=r"^[0-9a-fA-F]{32}$",
        confidence="baja",
        description="Resumen MD4 (128 bits), predecesor de MD5. Base también del hash NTLM",
        example="8a9d093f14f8701df17732b2bb182c74",
        reference="Hashcat -m 900 · John: raw-md4",
    ),
    HashSignature(
        name="NTLM",
        pattern=r"^[0-9a-fA-F]{32}$",
        confidence="baja",
        description=(
            "MD4 de la contraseña en UTF-16LE. Usado por Windows/Active "
            "Directory. Misma forma exacta que MD5 y MD4"
        ),
        example="8846f7eaee8fb117ad06bdd830b7586c",
        reference="Hashcat -m 1000 · John: nt",
    ),
    HashSignature(
        name="LM hash",
        pattern=r"^[0-9a-fA-F]{32}$",
        confidence="baja",
        description=(
            "Hash LAN Manager, formato de Windows anterior a NTLM. "
            "Divide la contraseña en dos mitades de 7 caracteres — "
            "extremadamente débil"
        ),
        example="e52cac67419a9a224a3b108f3fa6cb6d",
        reference="Hashcat -m 3000 · John: lm",
    ),
    HashSignature(
        name="HAVAL-128",
        pattern=r"^[0-9a-fA-F]{32}$",
        confidence="baja",
        description="Variante de 128 bits de la familia HAVAL. Poco común hoy en día (valor ilustrativo)",
        example=_hex_placeholder(32),
        reference="John: haval-128-4",
    ),
    HashSignature(
        name="RipeMD-128",
        pattern=r"^[0-9a-fA-F]{32}$",
        confidence="baja",
        description="Variante de 128 bits de RIPEMD, poco usada en la práctica (valor ilustrativo)",
        example=_hex_placeholder(32),
    ),
    HashSignature(
        name="Tiger-128",
        pattern=r"^[0-9a-fA-F]{32}$",
        confidence="baja",
        description="Truncamiento a 128 bits del algoritmo Tiger (valor ilustrativo)",
        example=_hex_placeholder(32),
    ),
    # -------------------------------------------------------------------
    # Grupo de 40 caracteres hexadecimales
    # -------------------------------------------------------------------
    HashSignature(
        name="SHA-1",
        pattern=r"^[0-9a-fA-F]{40}$",
        confidence="baja",
        description="Resumen SHA-1 (160 bits). Considerado roto para uso criptográfico desde 2017",
        example="5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
        reference="Hashcat -m 100 · John: raw-sha1",
    ),
    HashSignature(
        name="RipeMD-160",
        pattern=r"^[0-9a-fA-F]{40}$",
        confidence="baja",
        description="Resumen RIPEMD de 160 bits, usado en Bitcoin (junto con SHA-256)",
        example="2c08e8f5884750a7b99f6f2f342fc638db25ff31",
        reference="Hashcat -m 6000",
    ),
    HashSignature(
        name="Tiger-160",
        pattern=r"^[0-9a-fA-F]{40}$",
        confidence="baja",
        description="Variante de 160 bits del algoritmo Tiger (valor ilustrativo)",
        example=_hex_placeholder(40),
    ),
    HashSignature(
        name="HAVAL-160",
        pattern=r"^[0-9a-fA-F]{40}$",
        confidence="baja",
        description="Variante de 160 bits de la familia HAVAL (valor ilustrativo)",
        example=_hex_placeholder(40),
    ),
    HashSignature(
        name="HAS-160",
        pattern=r"^[0-9a-fA-F]{40}$",
        confidence="baja",
        description="Algoritmo coreano usado en el estándar KCDSA (valor ilustrativo)",
        example=_hex_placeholder(40),
    ),
    # -------------------------------------------------------------------
    # Grupo de 56 caracteres hexadecimales
    # -------------------------------------------------------------------
    HashSignature(
        name="SHA-224",
        pattern=r"^[0-9a-fA-F]{56}$",
        confidence="baja",
        description="Variante truncada de SHA-256 (224 bits de salida)",
        example="d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01",
        reference="Hashcat -m 1300",
    ),
    HashSignature(
        name="SHA3-224",
        pattern=r"^[0-9a-fA-F]{56}$",
        confidence="baja",
        description="Variante de 224 bits de SHA-3 (familia Keccak, estandarizada por NIST)",
        example="c3f847612c3780385a859a1993dfd9fe7c4e6d7f477148e527e9374c",
        reference="Hashcat -m 17300",
    ),
    # -------------------------------------------------------------------
    # Grupo de 64 caracteres hexadecimales
    # -------------------------------------------------------------------
    HashSignature(
        name="SHA-256",
        pattern=r"^[0-9a-fA-F]{64}$",
        confidence="baja",
        description="Resumen SHA-256 (256 bits). El más usado hoy en día para integridad de datos",
        example="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        reference="Hashcat -m 1400 · John: raw-sha256",
    ),
    HashSignature(
        name="SHA3-256",
        pattern=r"^[0-9a-fA-F]{64}$",
        confidence="baja",
        description="Variante de 256 bits de SHA-3, misma longitud que SHA-256",
        example="c0067d4af4e87f00dbac63b6156828237059172d1bbeac67427345d6a9fda484",
        reference="Hashcat -m 17400",
    ),
    HashSignature(
        name="Keccak-256",
        pattern=r"^[0-9a-fA-F]{64}$",
        confidence="baja",
        description=(
            "Keccak con el relleno original (pre-estandarización NIST). "
            "Usado por Ethereum para direcciones y hashes de bloque"
        ),
        example="b68fe43f0d1a0d7aef123722670be50268e15365401c442f8806ef83b612976b",
        reference="Hashcat -m 17800 (Keccak-256)",
    ),
    HashSignature(
        name="BLAKE2s-256",
        pattern=r"^[0-9a-fA-F]{64}$",
        confidence="baja",
        description="Variante rápida de BLAKE2 optimizada para 32 bits, salida de 256 bits",
        example="4c81099df884bd6e14a639d648bccd808512e48af211ae4f44d545ea6d5e5f2b",
    ),
    HashSignature(
        name="GOST R 34.11-94",
        pattern=r"^[0-9a-fA-F]{64}$",
        confidence="baja",
        description="Estándar de hash ruso, salida de 256 bits (valor ilustrativo)",
        example=_hex_placeholder(64),
        reference="Hashcat -m 6900",
    ),
    # -------------------------------------------------------------------
    # Grupo de 96 caracteres hexadecimales
    # -------------------------------------------------------------------
    HashSignature(
        name="SHA-384",
        pattern=r"^[0-9a-fA-F]{96}$",
        confidence="baja",
        description="Variante truncada de SHA-512 (384 bits de salida)",
        example=(
            "a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2be"
            "bc45583d446c598660c94ce680c47d19c30783a7"
        ),
        reference="Hashcat -m 10800",
    ),
    HashSignature(
        name="SHA3-384",
        pattern=r"^[0-9a-fA-F]{96}$",
        confidence="baja",
        description="Variante de 384 bits de SHA-3, misma longitud que SHA-384",
        example=(
            "9c1565e99afa2ce7800e96a73c125363c06697c5674d59f227b3368f"
            "d00b85ead506eefa90702673d873cb2c9357eafc"
        ),
        reference="Hashcat -m 17500",
    ),
    # -------------------------------------------------------------------
    # Grupo de 128 caracteres hexadecimales
    # -------------------------------------------------------------------
    HashSignature(
        name="SHA-512",
        pattern=r"^[0-9a-fA-F]{128}$",
        confidence="baja",
        description="Resumen SHA-512 (512 bits). Usado cuando se necesita máxima resistencia a colisiones",
        example=(
            "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c"
            "706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c9"
            "5385ffab0cacbc86"
        ),
        reference="Hashcat -m 1700 · John: raw-sha512",
    ),
    HashSignature(
        name="SHA3-512",
        pattern=r"^[0-9a-fA-F]{128}$",
        confidence="baja",
        description="Variante de 512 bits de SHA-3, misma longitud que SHA-512",
        example=(
            "e9a75486736a550af4fea861e2378305c4a555a05094dee1dca2f68a"
            "fea49cc3a50e8de6ea131ea521311f4d6fb054a146e8282f8e35ff2e"
            "6368c1a62e909716"
        ),
        reference="Hashcat -m 17600",
    ),
    HashSignature(
        name="BLAKE2b-512",
        pattern=r"^[0-9a-fA-F]{128}$",
        confidence="baja",
        description="Variante de BLAKE2 optimizada para 64 bits, salida completa de 512 bits",
        example=(
            "7c863950ac93c93692995e4732ce1e1466ad74a775352ffbaaf2a4a4"
            "ce9b549d0b414a1f3150452be6c7c72c694a7cb46f76452917298d33"
            "e67611f0a42addb8"
        ),
        reference="Hashcat -m 600",
    ),
    HashSignature(
        name="Whirlpool",
        pattern=r"^[0-9a-fA-F]{128}$",
        confidence="baja",
        description="Función hash de 512 bits basada en una estructura tipo AES (valor ilustrativo)",
        example=_hex_placeholder(128),
        reference="Hashcat -m 6100",
    ),
    # =====================================================================
    # A partir de aquí: formatos ESTRUCTURADOS con marcador propio.
    # Estos SÍ se identifican con alta confianza porque el prefijo (y a
    # veces los separadores internos) son exclusivos de ese formato
    # =====================================================================
    HashSignature(
        name="bcrypt",
        pattern=r"^\$2[abxy]\$\d{2}\$[./A-Za-z0-9]{53}$",
        confidence="alta",
        description=(
            "Algoritmo adaptativo basado en Blowfish. El segmento "
            "'\\d{2}' es el costo (rondas = 2^costo). Estándar de facto "
            "para contraseñas web durante más de una década"
        ),
        example="$2b$12$OZTNj7sIp2O8SEFvymeuH.7aMDpgQHThee7FCMstQvSBOxQcPf/qS",
        reference="Hashcat -m 3200 · John: bcrypt",
    ),
    HashSignature(
        name="MD5 crypt ($1$)",
        pattern=r"^\$1\$[./0-9A-Za-z]{0,8}\$[./0-9A-Za-z]{22}$",
        confidence="alta",
        description="Formato crypt(3) de Unix basado en MD5, usado en /etc/shadow en sistemas antiguos",
        example="$1$Ur1bckMg$Jqn1mNaZPXvmTohDHiWYN1",
        reference="Hashcat -m 500 · John: md5crypt",
    ),
    HashSignature(
        name="Apache MD5 (apr1)",
        pattern=r"^\$apr1\$[./0-9A-Za-z]{0,8}\$[./0-9A-Za-z]{22}$",
        confidence="alta",
        description="Variante de MD5 crypt usada por Apache en archivos .htpasswd",
        example="$apr1$U0il40z5$idevHhoJdk/10jvzo99Xq1",
        reference="Hashcat -m 1600",
    ),
    HashSignature(
        name="SHA-256 crypt ($5$)",
        pattern=r"^\$5\$(rounds=\d+\$)?[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{43}$",
        confidence="alta",
        description="Formato crypt(3) basado en SHA-256, común en /etc/shadow de Linux moderno",
        example="$5$QmnK3xlS3rqEoTTE$ZTN4ZP4vh9GnELMg1jbIsG1SHXkktYySh5xpBtU/tM3",
        reference="Hashcat -m 7400 · John: sha256crypt",
    ),
    HashSignature(
        name="SHA-512 crypt ($6$)",
        pattern=r"^\$6\$(rounds=\d+\$)?[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{86}$",
        confidence="alta",
        description="Formato crypt(3) basado en SHA-512. Es el que usa /etc/shadow por defecto en la mayoría de distros Linux",
        example=(
            "$6$FTaBc/qzcxmppO4A$F.RJoItGx8SSZo0B1.aM8f3bNIXyGg5IjhbYb"
            "BXw78AzZQpLP3Hfm4QNGXJjZa3J9iWJMOGZzM5O3LoSE00Pe/"
        ),
        reference="Hashcat -m 1800 · John: sha512crypt",
    ),
    HashSignature(
        name="phpass / WordPress / phpBB3",
        pattern=r"^\$[PH]\$[./0-9A-Za-z]{31}$",
        confidence="alta",
        description="Formato 'portable hash' usado por WordPress, phpBB3 y muchos CMS en PHP",
        example="$P$HShSkGjER9KtxI26d44o2.6CsNGxXZ/",
        reference="Hashcat -m 400 · John: phpass",
    ),
    HashSignature(
        name="Argon2id",
        pattern=r"^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$",
        confidence="alta",
        description=(
            "Ganador del Password Hashing Competition (2015). Variante "
            "híbrida, recomendada por defecto para contraseñas nuevas"
        ),
        example=(
            "$argon2id$v=19$m=65536,t=3,p=4$magufk5uRNHYlGCPodO54Q$"
            "LI0k5wvGUq3N/S/CmCFMSLA5UyMfYc2IxwvaKSqRlm4"
        ),
        reference="Hashcat -m 32200 · John: argon2",
    ),
    HashSignature(
        name="Argon2i",
        pattern=r"^\$argon2i\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$",
        confidence="alta",
        description="Variante de Argon2 optimizada contra ataques de canal lateral (side-channel)",
        example=(
            "$argon2i$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$"
            "N7SW7Qk1lfhZPeOqz5vaTLSlxdCEClm/l8CBXq4xeWc"
        ),
        reference="Hashcat -m 32100",
    ),
    HashSignature(
        name="Argon2d",
        pattern=r"^\$argon2d\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$",
        confidence="alta",
        description="Variante de Argon2 optimizada contra ataques con GPU (menos resistente a side-channel)",
        example=(
            "$argon2d$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$"
            "4uCdE/ZhuVzzF7hgyUZWNIVIO6QxMz2OTd89C8tRAf8"
        ),
        reference="Hashcat -m 32000",
    ),
    HashSignature(
        name="scrypt (aproximado)",
        pattern=r"^\$?scrypt\$.+$",
        confidence="media",
        description=(
            "KDF con costo de memoria configurable (N, r, p). ATENCIÓN: "
            "a diferencia de bcrypt/argon2, la codificación de scrypt "
            "NO está estandarizada — Django, Node.js y libsodium usan "
            "diseños distintos, por lo que esta detección es heurística"
        ),
        example="$scrypt$ln=14,r=8,p=1$c29tZXNhbHQ$aGFzaHZhbHVlcGxhY2Vob2xkZXI",
        reference="Hashcat -m 8900 / 15700 según variante",
    ),
    HashSignature(
        name="MySQL 4.1+/5.x",
        pattern=r"^\*[0-9A-Fa-f]{40}$",
        confidence="alta",
        description="Función PASSWORD() moderna de MySQL: asterisco + SHA-1 doble en mayúsculas",
        example="*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19",
        reference="Hashcat -m 300 · John: mysql-sha1",
    ),
    HashSignature(
        name="LDAP {SHA}",
        pattern=r"^\{SHA\}[A-Za-z0-9+/]{27}=$",
        confidence="alta",
        description="SHA-1 sin sal codificado en Base64, con el prefijo literal '{SHA}' (esquema LDAP userPassword)",
        example="{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=",
        reference="Hashcat -m 101",
    ),
    HashSignature(
        name="LDAP {SSHA}",
        pattern=r"^\{SSHA\}[A-Za-z0-9+/]{20,}={0,2}$",
        confidence="alta",
        description="SHA-1 CON sal (salt concatenada tras el resumen, ambos en Base64), prefijo '{SSHA}'",
        example="{SSHA}y4CSlh3SczaLu3qlv6uXlJ2Jrwu4F4JQ",
        reference="Hashcat -m 111",
    ),
    HashSignature(
        name="Django PBKDF2-SHA256",
        pattern=r"^pbkdf2_sha256\$\d+\$[A-Za-z0-9]+\$[A-Za-z0-9+/]+=*$",
        confidence="alta",
        description="Formato por defecto de contraseñas en Django: algoritmo$iteraciones$sal$hash",
        example="pbkdf2_sha256$29000$hcMTlDhSJQuD$W6dFRfWD1S7G0C7y4qke/BhUpAh7ulH6DG9Jsbb8ZRU=",
        reference="Hashcat -m 10000",
    ),
    HashSignature(
        name="Django PBKDF2-SHA1",
        pattern=r"^pbkdf2_sha1\$\d+\$[A-Za-z0-9]+\$[A-Za-z0-9+/]+=*$",
        confidence="alta",
        description="Variante más antigua del hasher PBKDF2 de Django, basada en SHA-1",
        example="pbkdf2_sha1$131000$VnV1MS5V8EFW$grBDszhsdYPq+lVCvzwY99ilfXA=",
        reference="Hashcat -m 12000",
    ),
    HashSignature(
        name="JWT (no es un hash)",
        pattern=r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$",
        confidence="alta",
        description=(
            "Un JSON Web Token, NO un hash de contraseña: son tres "
            "segmentos Base64-URL (header.payload.signature). "
            "'eyJ' es el Base64 de '{\"'"
        ),
        example=(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "dGhpc19pc19hX3BsYWNlaG9sZGVy"
        ),
        reference="No aplica a Hashcat/John — no es un hash de contraseña",
    ),
    HashSignature(
        name="Unix DES crypt (clásico)",
        pattern=r"^[./0-9A-Za-z]{13}$",
        confidence="media",
        description=(
            "El crypt(3) original de Unix (1979): 2 caracteres de sal + "
            "11 de resumen, sin marcador de prefijo. Limitado a 8 "
            "caracteres de contraseña — obsoleto pero aún se encuentra"
        ),
        example="abJnggxhB/yWI",
        reference="Hashcat -m 1500 · John: descrypt",
    ),
]


# =============================================================================
# Prefijos conocidos — para el diagnóstico rápido de "señales" en la CLI
# =============================================================================
# Ordenados del más largo al más corto: al comprobar con startswith()
# queremos que "$argon2id$" gane sobre un genérico "$argon2" si ambos
# calzaran, así que probamos primero los más específicos

_KNOWN_PREFIXES: list[str] = sorted(
    [
        "$argon2id$",
        "$argon2i$",
        "$argon2d$",
        "$2a$",
        "$2b$",
        "$2x$",
        "$2y$",
        "$apr1$",
        "$scrypt$",
        "scrypt$",
        "$6$",
        "$5$",
        "$1$",
        "$P$",
        "$H$",
        "{SSHA}",
        "{SHA}",
        "pbkdf2_sha256$",
        "pbkdf2_sha1$",
        "eyJ",
        "*",
    ],
    key=len,
    reverse=True,
)


def detect_prefix(value: str) -> str | None:
    """
    Devuelve el marcador de formato conocido con el que empieza `value`,
    o None si no coincide con ninguno de la lista. Es una señal de
    diagnóstico independiente de `identify_hash()` — sirve para que el
    usuario vea POR QUÉ el programa sospecha de un formato dado
    """
    for prefix in _KNOWN_PREFIXES:
        if value.startswith(prefix):
            return prefix
    return None


def detect_charset(value: str) -> str:
    """
    Clasifica el alfabeto de caracteres usado en `value`. Es una señal
    de diagnóstico: no decide la identificación por sí sola, pero
    ayuda a entender por qué ciertos candidatos aparecen o no
    """
    if re.fullmatch(r"[0-9a-fA-F]+", value):
        return "hexadecimal (0-9, a-f)"
    if re.fullmatch(r"[0-9]+", value):
        return "solo dígitos decimales"
    if re.fullmatch(r"[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*", value) and "." in value:
        return "Base64-URL con segmentos separados por '.' (típico de JWT)"
    if re.fullmatch(r"[A-Za-z0-9+/]+=*", value):
        return "Base64 estándar (A-Za-z0-9+/, con o sin relleno '=')"
    if re.fullmatch(r"[./0-9A-Za-z]+", value):
        return "Base64 estilo crypt(3) (./0-9A-Za-z)"
    if re.fullmatch(r"[A-Za-z0-9_-]+", value):
        return "Base64-URL (A-Za-z0-9-_, sin relleno)"
    return "mixto / caracteres especiales (probablemente incluye '$' o '{}' como delimitadores)"


# =============================================================================
# HashMatch — resultado de comparar un valor contra una firma
# =============================================================================


@dataclass(frozen=True, slots=True)
class HashMatch:
    """Una firma que coincidió con el valor analizado."""

    signature: HashSignature


# =============================================================================
# identify_hash() — función pura, sin E/S, fácil de testear
# =============================================================================


def identify_hash(value: str) -> list[HashMatch]:
    """
    Compara `value` contra cada firma de `SIGNATURES` y devuelve las
    que coinciden, ordenadas por confianza (alta -> media -> baja) y,
    dentro del mismo nivel, alfabéticamente por nombre

    No lanza excepciones: una cadena vacía o con caracteres raros
    simplemente no coincidirá con ninguna firma y se devuelve una
    lista vacía
    """
    value = value.strip()
    matches = [
        HashMatch(signature=sig)
        for sig in SIGNATURES
        if re.fullmatch(sig.pattern, value)
    ]
    matches.sort(
        key=lambda m: (_CONFIDENCE_ORDER[m.signature.confidence], m.signature.name)
    )
    return matches


# =============================================================================
# Capa de presentación — mantiene el formato de salida separado de
# la lógica de identificación
# =============================================================================


def _render_signals(value: str, console: Console) -> None:
    """Muestra las tres señales crudas: longitud, charset y prefijo."""
    prefix = detect_prefix(value)
    panel = Panel(
        f"[bold]Longitud:[/bold] {len(value)} caracteres\n"
        f"[bold]Charset:[/bold] {detect_charset(value)}\n"
        f"[bold]Prefijo detectado:[/bold] "
        + (f"[bright_green]{prefix}[/bright_green]" if prefix else "[dim]ninguno[/dim]"),
        title="Señales",
        border_style="blue",
    )
    console.print(panel)


def _render_matches(matches: list[HashMatch], console: Console) -> None:
    """Imprime los candidatos encontrados como una tabla enriquecida."""
    if not matches:
        console.print(
            "[red]Sin coincidencias.[/red] Ningún formato conocido calza "
            "con esta longitud/charset/prefijo. Puede ser un formato no "
            "incluido en esta tabla, un hash truncado, o datos codificados "
            "que no son un hash en absoluto."
        )
        return

    table = Table(title="Candidatos", show_lines=False)
    table.add_column("algoritmo/formato", style="bold white", no_wrap=True)
    table.add_column("confianza", no_wrap=True)
    table.add_column("descripción", style="dim")
    table.add_column("referencia", style="dim", no_wrap=True)

    for match in matches:
        sig = match.signature
        color = _CONFIDENCE_COLORS[sig.confidence]
        table.add_row(
            sig.name,
            f"[{color}]{sig.confidence}[/{color}]",
            sig.description,
            sig.reference or "—",
        )
    console.print(table)

    ambiguous = any(m.signature.confidence == "baja" for m in matches)
    if ambiguous:
        console.print(
            "\n[cyan]Nota:[/cyan] algunos candidatos comparten exactamente "
            "la misma longitud y charset. Sin contexto adicional (de qué "
            "sistema salió el hash) no es posible distinguirlos solo por "
            "su forma."
        )


def _render_signature_catalog(console: Console) -> None:
    """Implementa `--list`: muestra toda la tabla de firmas conocidas."""
    table = Table(title=f"Catálogo de firmas conocidas ({len(SIGNATURES)})")
    table.add_column("algoritmo/formato", style="bold white")
    table.add_column("confianza", no_wrap=True)
    table.add_column("ejemplo", style="dim")

    for sig in SIGNATURES:
        color = _CONFIDENCE_COLORS[sig.confidence]
        table.add_row(
            sig.name,
            f"[{color}]{sig.confidence}[/{color}]",
            sig.example,
        )
    console.print(table)


# =============================================================================
# argparse — separado de main() para que los tests puedan invocarlo
# =============================================================================


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hashid-mini",
        description=(
            "Identifica el tipo probable de un hash a partir de su "
            "prefijo, longitud y charset."
        ),
    )
    parser.add_argument(
        "value",
        nargs="?",
        help=(
            "La cadena a identificar. Si se omite, se lee una línea "
            "desde stdin (útil para tuberías: echo '<hash>' | hashid-mini)."
        ),
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Muestra el catálogo completo de firmas conocidas y termina.",
    )
    return parser


# =============================================================================
# main() — códigos de salida pensados para uso en scripts
# =============================================================================
# 0 -> se encontró al menos un candidato de confianza "alta"
# 1 -> solo se encontraron candidatos "media"/"baja" (ambiguo)
# 2 -> no hubo ninguna coincidencia, o la entrada estaba vacía


def main() -> int:
    parser = _build_argument_parser()
    args = parser.parse_args()
    console = Console()

    if args.list:
        _render_signature_catalog(console)
        return 0

    value = args.value
    if value is None:
        # Sin argumento posicional: intentamos leer una línea de stdin.
        # Si stdin es una terminal interactiva (nadie canalizó nada),
        # es más útil mostrar el mensaje de uso que quedarse colgado
        # esperando que el usuario escriba algo a ciegas
        if sys.stdin.isatty():
            parser.error("Debes indicar un hash como argumento o por stdin.")
        value = sys.stdin.readline()

    value = value.strip()
    if not value:
        console.print("[red]Error:[/red] la cadena de entrada está vacía.")
        return 2

    _render_signals(value, console)
    matches = identify_hash(value)
    _render_matches(matches, console)

    if not matches:
        return 2
    if matches[0].signature.confidence == "alta":
        return 0
    return 1


# Guardia estándar de "si se ejecuta directamente como script" — permite
# que los tests importen este archivo sin disparar main()
if __name__ == "__main__":
    sys.exit(main())
