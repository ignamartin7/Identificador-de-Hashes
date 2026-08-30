"""
©AngelaMos | 2026
test_hash_identifier.py

Suite de pruebas para hash_identifier.py

Tres capas de prueba:
  1. Consistencia interna: el `example` de CADA firma debe calzar con
     su propio `pattern`. Esto evita el error clásico de escribir una
     regex con una longitud equivocada sin darnos cuenta
  2. Casos reales: hashes/valores generados con hashlib, bcrypt,
     argon2-cffi y passlib (no inventados a mano) deben identificarse
     con el algoritmo esperado en primer lugar
  3. Comportamiento del identificador: ambigüedad, entradas vacías,
     mayúsculas/minúsculas, espacios en blanco
"""

import re

import pytest

from hash_identifier import (
    SIGNATURES,
    detect_charset,
    detect_prefix,
    identify_hash,
)

# =============================================================================
# 1. Cada firma debe reconocer su propio ejemplo
# =============================================================================


@pytest.mark.parametrize(
    "signature",
    SIGNATURES,
    ids=[sig.name for sig in SIGNATURES],
)
def test_signature_example_matches_its_own_pattern(signature):
    assert re.fullmatch(signature.pattern, signature.example), (
        f"El ejemplo de '{signature.name}' no calza con su propio patrón:\n"
        f"  pattern = {signature.pattern!r}\n"
        f"  example = {signature.example!r} (len={len(signature.example)})"
    )


def test_signature_example_appears_in_identify_hash_results():
    """Cada ejemplo, al pasarlo por identify_hash(), debe listar a su
    propia firma entre los resultados (no necesariamente en primer
    lugar, si comparte forma con otros algoritmos)."""
    for sig in SIGNATURES:
        names = {m.signature.name for m in identify_hash(sig.example)}
        assert sig.name in names


# =============================================================================
# 2. Casos reales — verificados con hashlib/bcrypt/argon2-cffi/passlib
# =============================================================================


def test_md5_of_password():
    matches = identify_hash("5f4dcc3b5aa765d61d8327deb882cf99")
    names = [m.signature.name for m in matches]
    assert "MD5" in names
    # 32 hex es ambiguo: deben aparecer varios candidatos, todos "baja"
    assert len(names) >= 3
    assert all(m.signature.confidence == "baja" for m in matches)


def test_sha256_of_password():
    matches = identify_hash(
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    )
    names = [m.signature.name for m in matches]
    assert "SHA-256" in names


def test_bcrypt_is_unambiguous_and_high_confidence():
    value = "$2b$12$OZTNj7sIp2O8SEFvymeuH.7aMDpgQHThee7FCMstQvSBOxQcPf/qS"
    matches = identify_hash(value)
    assert len(matches) == 1
    assert matches[0].signature.name == "bcrypt"
    assert matches[0].signature.confidence == "alta"


def test_argon2id_real_hash():
    value = (
        "$argon2id$v=19$m=65536,t=3,p=4$magufk5uRNHYlGCPodO54Q$"
        "LI0k5wvGUq3N/S/CmCFMSLA5UyMfYc2IxwvaKSqRlm4"
    )
    matches = identify_hash(value)
    assert len(matches) == 1
    assert matches[0].signature.name == "Argon2id"


def test_sha512crypt_real_hash():
    value = (
        "$6$FTaBc/qzcxmppO4A$F.RJoItGx8SSZo0B1.aM8f3bNIXyGg5IjhbYb"
        "BXw78AzZQpLP3Hfm4QNGXJjZa3J9iWJMOGZzM5O3LoSE00Pe/"
    )
    matches = identify_hash(value)
    names = [m.signature.name for m in matches]
    assert "SHA-512 crypt ($6$)" in names


def test_mysql41_prefix_detected():
    value = "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19"
    matches = identify_hash(value)
    assert len(matches) == 1
    assert matches[0].signature.name == "MySQL 4.1+/5.x"
    assert detect_prefix(value) == "*"


def test_jwt_format_detected_and_flagged_as_not_a_hash():
    value = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dGhpc19pc19hX3BsYWNlaG9sZGVy"
    )
    matches = identify_hash(value)
    assert any("JWT" in m.signature.name for m in matches)
    assert detect_prefix(value) == "eyJ"


def test_django_pbkdf2_sha256_real_hash():
    value = (
        "pbkdf2_sha256$29000$hcMTlDhSJQuD$"
        "W6dFRfWD1S7G0C7y4qke/BhUpAh7ulH6DG9Jsbb8ZRU="
    )
    matches = identify_hash(value)
    assert len(matches) == 1
    assert matches[0].signature.name == "Django PBKDF2-SHA256"


def test_unix_des_crypt_real_hash():
    matches = identify_hash("abJnggxhB/yWI")
    names = [m.signature.name for m in matches]
    assert "Unix DES crypt (clásico)" in names


# =============================================================================
# 3. Comportamiento general del identificador
# =============================================================================


def test_empty_string_has_no_matches():
    assert identify_hash("") == []


def test_whitespace_is_stripped_before_matching():
    padded = "  5f4dcc3b5aa765d61d8327deb882cf99  \n"
    assert identify_hash(padded) == identify_hash(padded.strip())


def test_garbage_input_has_no_matches():
    assert identify_hash("no-soy-un-hash-válido-😀") == []


def test_uppercase_hex_is_still_recognized():
    # MD5 en mayúsculas: nuestras firmas hex son case-insensitive
    upper = "5F4DCC3B5AA765D61D8327DEB882CF99"
    matches = identify_hash(upper)
    names = [m.signature.name for m in matches]
    assert "MD5" in names


def test_matches_are_sorted_high_confidence_first():
    # Mezclamos un valor "alta" (bcrypt) — no hay ambigüedad que ordenar,
    # así que probamos el orden con un valor de 32 hex (todo "baja")
    # y confirmamos que la lista completa está ordenada correctamente
    matches = identify_hash("5f4dcc3b5aa765d61d8327deb882cf99")
    confidences = [m.signature.confidence for m in matches]
    order = {"alta": 0, "media": 1, "baja": 2}
    assert confidences == sorted(confidences, key=lambda c: order[c])


# =============================================================================
# detect_charset / detect_prefix
# =============================================================================


def test_detect_charset_hex():
    assert "hexadecimal" in detect_charset("5f4dcc3b5aa765d61d8327deb882cf99")


def test_detect_charset_crypt_base64():
    # Necesita un '.' o '/' para diferenciarse del Base64 estándar
    # (que no incluye '.'); el ejemplo real de phpass tiene ambos
    assert "crypt" in detect_charset("HShSkGjER9KtxI26d44o2.6CsNGxXZ/")


def test_detect_prefix_none_for_raw_hex():
    assert detect_prefix("5f4dcc3b5aa765d61d8327deb882cf99") is None


def test_detect_prefix_bcrypt():
    value = "$2b$12$OZTNj7sIp2O8SEFvymeuH.7aMDpgQHThee7FCMstQvSBOxQcPf/qS"
    assert detect_prefix(value) == "$2b$"


def test_no_two_signatures_are_fully_duplicated():
    """Dos firmas no deberían tener el mismo (pattern, name) exacto —
    detecta copy-paste accidental al ampliar la tabla."""
    seen = set()
    for sig in SIGNATURES:
        key = (sig.name, sig.pattern)
        assert key not in seen, f"Firma duplicada: {sig.name}"
        seen.add(key)
