# Identificador de Hashes

Identifica el tipo probable de un hash a partir de **prefijo, longitud y
charset** — sin red, sin dependencias pesadas, un solo archivo Python.

## Qué hace

- Analiza una cadena y muestra sus tres señales crudas: **longitud**,
  **charset** (hexadecimal, Base64, Base64-URL, alfabeto de crypt(3)...)
  y **prefijo** conocido (`$2b$`, `$argon2id$`, `*`, `{SSHA}`, `eyJ`, etc.)
- Compara esas señales contra una tabla de ~45 formatos conocidos
  (MD5, SHA-1/224/256/384/512, SHA-3, bcrypt, Argon2i/d/id, scrypt,
  crypt(3) de Unix, MySQL, LDAP, PBKDF2 de Django, JWT...)
- Devuelve **todos los candidatos posibles**, no una única respuesta,
  clasificados en tres niveles de confianza:
  - **alta** — el formato tiene un marcador estructural propio
    (p. ej. `$2b$...` solo puede ser bcrypt)
  - **media** — reconocible por forma, sin competencia en esta tabla
  - **baja** — comparte longitud y charset con otros algoritmos
    (p. ej. cualquier cadena de 32 caracteres hex podría ser MD5,
    MD4 o NTLM — es matemáticamente imposible distinguirlos sin
    contexto adicional)

## Lo que NO hace

- No crackea ni fuerza bruta ningún hash
- No garantiza el algoritmo exacto en los casos ambiguos — solo
  reduce las opciones
- No decodifica el contenido de tokens como JWT, solo reconoce su forma

## Uso rápido

```bash
pip install rich
python hash_identifier.py '5f4dcc3b5aa765d61d8327deb882cf99'
python hash_identifier.py '$2b$12$OZTNj7sIp2O8SEFvymeuH.7aMDpgQHThee7FCMstQvSBOxQcPf/qS'
python hash_identifier.py --list          # ver el catálogo completo
echo 'algún-hash' | python hash_identifier.py   # también acepta stdin
```

Con `just` instalado:

```bash
just setup
just run -- '5f4dcc3b5aa765d61d8327deb882cf99'
just list
just test
```

## Códigos de salida (útiles en scripts)

| Código | Significado |
|---|---|
| `0` | Se encontró un candidato de confianza **alta** |
| `1` | Solo hubo candidatos de confianza **media/baja** (ambiguo) |
| `2` | Ninguna coincidencia, o la entrada estaba vacía |

## Extender la tabla de firmas

Toda la base de datos vive en la lista `SIGNATURES` dentro de
`hash_identifier.py`. Agregar un formato nuevo es tan simple como
añadir un `HashSignature(...)` más — el resto del programa lo recorre
automáticamente. Los tests (`test_hash_identifier.py`) validan que el
`example` de cada firma nueva calce con su propio `pattern`, así que
un error de longitud en una regex se detecta de inmediato.

## Tests

```bash
pip install pytest
pytest -v
```

67 casos: consistencia de cada firma contra su propio patrón, valores
reales generados con `hashlib`/`bcrypt`/`argon2-cffi`/`passlib`
(no inventados a mano), y comportamiento del identificador ante
entradas vacías, mayúsculas, espacios en blanco, etc.

## Licencia

AGPL 3.0
