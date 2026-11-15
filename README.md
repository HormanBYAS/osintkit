# osintkit

**Kit de OSINT para terminal, pensado para Void Linux.** Reúne reconocimiento de
DNS, web, IP, email, usuarios, teléfonos, criptomonedas, organizaciones,
amenazas, búsqueda, geolocalización y metadatos de archivos en una sola interfaz
de texto, con CLI, TUI y catálogo de herramientas.

- **Sin dependencias obligatorias**: Python 3.10+ y su biblioteca estándar.
- **303 capacidades** en 13 categorías: 100 módulos internos, 71 binarios
  externos opcionales y 132 recursos web.
- **2.617 sitios** para enumerar usuarios y emails, y **70 fuentes** de teléfono.
- **19 perfiles** de escaneo por tipo de objetivo.
- **Pasivo por defecto**: las herramientas activas solo se ejecutan si las
  seleccionas y confirmas autorización.
- Informes en **JSON, Markdown y HTML**.
- **Resumen final** con IPs, datos técnicos y enlaces destacados.
- Claves API por entorno o archivo de configuración, nunca obligatorias.
- Plugins en Python para ampliar catálogo y módulos.

> ⚠️ **Ética y legalidad.** Usa osintkit únicamente sobre sistemas, cuentas y
> datos para los que tengas autorización expresa. El reconocimiento no
> autorizado puede ser ilegal. Respeta la privacidad, los términos de servicio y
> la legislación aplicable. Los resultados provienen de terceros y pueden ser
> inexactos.

---

## Arranque rápido

```sh
# Void Linux
sudo xbps-install -S python3 git

git clone https://github.com/HormanBYAS/osintkit.git
cd osintkit

# Opción 1: ejecutar sin instalar
./bin/osintkit

# Opción 2: instalar en un entorno aislado
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
osintkit

# Opción 3: instalación de usuario con pipx
pipx install .
```

Al ejecutar `osintkit` sin argumentos se abre la TUI. Si no hay terminal
interactiva, usa la CLI:

```sh
osintkit scan example.com
osintkit scan -i                 # asistente: elige tipo de objetivo y perfil
osintkit scan 1.1.1.1 -p ip
osintkit scan analista -k username --all
osintkit scan analista@gmail.com
osintkit run dns_records example.com
osintkit list --kind domain --available
osintkit doctor -v
```

También existe el alias **`osintol`**. El lanzador de desarrollo está en
`bin/osintol` y el paquete instala ambos comandos. Para abrirlo desde cualquier
carpeta sin instalar el paquete:

```sh
mkdir -p ~/.local/bin
ln -sf "$PWD/bin/osintol" ~/.local/bin/osintol
osintol
```

Al ejecutarlo sin argumentos se abre la misma TUI que con `osintkit`. El alias
anterior `osinttools` fue reemplazado por `osintol`.

Cuando una herramienta devuelve puertos (Shodan InternetDB, Shodan, Censys,
nmap, naabu o masscan), cada puerto se muestra con su servicio:

```text
Puerto 22: SSH
Puerto 53: DNS
Puerto 443: HTTPS
Puerto 8443: HTTPS-alt
```

Si el puerto no está en el mapa de servicios habituales, se etiqueta como
`desconocido` en lugar de mostrar solo el número.

### Enlaces directos a perfiles

Las herramientas de email, teléfono y usuario primero comprueban si el dato
aparece en fuentes públicas y después enlazan a la página directa del perfil o
de la mención. Ya no se limitan a entregar una URL de Google o DuckDuckGo.

```text
✓ GitHub
  https://github.com/usuario
✓ Facebook
  https://www.facebook.com/usuario
✓ WhatsApp · contacto directo
  https://wa.me/34600123456
```

Cuando no se encuentra ningún perfil o mención directa, se muestra un enlace
de **Búsqueda manual** claramente etiquetado; no se presenta como si fuera un
perfil verificado. En teléfonos se añade además un enlace directo de
WhatsApp (`wa.me`) como contacto, indicando que la cuenta no se puede verificar
sin iniciar sesión. Los buscadores públicos pueden limitar las consultas, por
lo que la ausencia de resultados no demuestra que la cuenta no exista.

### Resumen final: IPs, datos técnicos y enlaces

Todos los resultados, especialmente los de teléfono, número y Gmail/email,
terminan con un bloque **RESUMEN FINAL** en la consola y la TUI, y con una
sección equivalente en JSON, Markdown y HTML. El bloque responde a dos
preguntas:

- **¿Apareció alguna dirección IP?** Se buscan IPv4 e IPv6 únicas en títulos,
  valores, URLs y metadatos, y se indica su ámbito (pública, privada, loopback)
  y las herramientas que las mencionan. Si no hay ninguna, se dice
  explícitamente `ninguna en los resultados`.
- **¿Qué enlaces conviene abrir?** Se seleccionan hasta 10 enlaces priorizando
  perfiles directos, URLs que no son páginas de búsqueda y hosts de alto valor
  (GitHub, LinkedIn, X/Twitter, WhatsApp, Truecaller, Gravatar, etc.). Las
  búsquedas manuales quedan al final y solo aparecen si aportan información.

También se resumen datos técnicos como ASN, MX, proveedor, país, región,
operador, tipo de línea o zona horaria. El bloque se genera al renderizar el
informe, por lo que no altera el conteo de herramientas ni de hallazgos.

```text
RESUMEN FINAL
   · Direcciones IP encontradas: ninguna en los resultados
   · Otros datos técnicos: 2 detectados; se muestran los más relevantes
   · MX: 5 gmail-smtp-in.l.google.com.
   · Proveedor: Google Workspace / Gmail
   · Enlaces destacados: 3 de 12 enlaces; ordenados por perfil directo y relevancia
   ✓ WhatsApp — perfil directo · Directorios y buscadores de teléfono
     https://wa.me/34600123456
```

### Búsqueda masiva de usuarios y emails

`username_mass` usa una base interna de **2.617 sitios** derivada de Maigret
(licencia MIT) y comprueba el alias con concurrencia, timeout por petición y
marcadores de presencia/ausencia para reducir falsos positivos. El perfil
`username` la ejecuta por defecto sobre **los 2.617 sitios**; `username-quick`
omite la base masiva y `username-deep` añade enumeradores externos opcionales.

`email_mass` reutiliza esos mismos 2.617 sitios para un email o Gmail. Como la
base busca nombres de usuario, se utiliza la **parte local** de la dirección:
`analista@gmail.com` se comprueba como `analista`. En Gmail y Googlemail se
elimina el sufijo `+etiqueta` (`analista+osint@gmail.com` también se busca como
`analista`). Los perfiles `email` y `email-deep` la ejecutan por defecto;
`email-quick` omite la base masiva.

```sh
# Perfil normal: perfiles populares + base masiva completa
osintkit scan analista -k username
osintkit scan analista@gmail.com

# Solo la comprobación rápida
osintkit scan analista -k username -p username-quick
osintkit scan analista@gmail.com -p email-quick

# Herramientas masivas sueltas
osintkit run username_mass analista
osintkit run email_mass analista@gmail.com

# Limitar el escaneo y ajustar concurrencia
osintkit config set username_mass_limit 2000   # 0 = todos los sitios
osintkit config set username_mass_workers 48
osintkit config set username_mass_timeout 8
osintkit config set email_mass_limit 2000
osintkit config set email_mass_workers 48
osintkit config set email_mass_timeout 8
```

> La parte local de un email puede coincidir con el alias de otras personas.
> Los resultados de `email_mass` son **perfiles posibles**, no una prueba de
> que pertenezcan al titular de la cuenta. Para confirmar una cuenta de Google,
> usa `ghunt` (perfil `email-deep`) con autorización.

La base se puede actualizar desde Maigret y el archivo
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) conserva la atribución y la
licencia. Un escaneo de 2.000+ sitios tarda varios minutos y algunos servicios
pueden responder con login, captcha o límites; esos casos se muestran como
`Sin verificar`, no como cuentas inexistentes.

### Teléfonos: 70 fuentes

`phone_sources` genera enlaces a 70 directorios, buscadores inversos, bases de
reputación y contactos directos (WhatsApp, Telegram, Signal, Epieos). Los
directorios regionales están etiquetados por país. Además de `phone_dork`,
están disponibles `phone_veriphone`, `phone_abstract` y `phone_twilio` para
quien tenga clave API.

```sh
osintkit scan "+34 600 123 456" -k phone
osintkit run phone_sources "+34 600 123 456"
osintkit run phone_dork "+34 600 123 456"
```

---

## Interfaz TUI

Al entrar en **Escanear objetivo** la TUI pregunta primero **qué es el
objetivo** (correo/Gmail, usuario, dominio, teléfono, IP, URL, organización,
criptomoneda, hash, archivo o texto). Después pide el valor y deja elegir la
profundidad del escaneo. El informe se abre automáticamente al terminar y se
puede recorrer con las flechas.

| Tecla | Acción |
|---|---|
| `↑` `↓` / `j` `k` | mover por menús, tipos, perfiles y resultados |
| `Enter` | abrir, confirmar o escanear |
| `Esc` | volver o cancelar un escaneo en curso |
| `a` | autorizar/desautorizar técnicas activas en el perfil elegido |
| `e` | cambiar el objetivo |
| `b` | volver a elegir el tipo de objetivo |
| `g` / `G` | ir al inicio / final de resultados |
| `s` | guardar informes del último escaneo |
| `q` | salir |

La TUI muestra el progreso por herramienta, los hallazgos con colores de alto
contraste, el catálogo navegable y el estado de dependencias y claves. En los
resultados, el nombre del sitio aparece en verde, el detalle en blanco y la URL
en cian subrayado, de forma parecida a Maigret.

---

## Tipos de objetivo y perfiles

Tipos detectados automáticamente:

`domain`, `ip`, `email`, `username`, `phone`, `org`, `crypto`, `url`, `hash`,
`file`, `keyword`.

Perfiles disponibles:

| Perfil | Objetivo | Contenido |
|---|---|---|
| `domain` | dominio | DNS, certificados, WHOIS/RDAP, HTTP/TLS, archivo |
| `domain-deep` | dominio | + subfinder, amass, httpx, nuclei, ffuf… (activo) |
| `ip` | IP | geolocalización, ASN, RDAP, reputación, DNSBL |
| `ip-deep` | IP | + nmap, masscan, traceroute (activo) |
| `email` | email | validación, Gravatar, PGP, brechas, perfiles y 2.617 sitios |
| `email-quick` | email | solo validación y perfiles directos (sin base masiva) |
| `email-deep` | email | 2.617 sitios + holehe, h8mail, ghunt (activo) |
| `username` | alias | perfiles populares + 2.617 sitios de la base interna |
| `username-quick` | alias | solo perfiles populares (sin base masiva) |
| `username-deep` | alias | 2.000+ sitios + sherlock, maigret, social-analyzer |
| `phone` | teléfono | país, formato, operador, perfiles y 70 directorios |
| `phone-deep` | teléfono | + phoneinfoga, APIs y buscadores de identificación |
| `crypto` | dirección | BTC, ETH, otras cadenas, fraude |
| `org` | organización | registros mercantiles, sanciones, Wikidata, mapas |
| `url` | URL | HTTP, TLS, tecnologías, archivo, reputación |
| `url-deep` | URL | + crawlers y escáneres activos |
| `hash` | hash | VirusTotal, MalwareBazaar, ThreatFox, OTX |
| `file` | archivo | hashes, EXIF, PDF, strings, secretos |
| `keyword` | texto | buscadores, foros, wikis, archivos |

Fuerza un tipo o un perfil:

```sh
osintkit scan ejemplo.com -k domain -p domain
osintkit scan 8.8.8.8 -p ip-deep --active --yes
```

Los perfiles `-deep` incluyen herramientas activas. osintkit las omite salvo
que pases `--active`; si lo haces, pide confirmación explícita (o `--yes` en
automatizaciones).

---

## Comandos

```text
osintkit [tui]                 interfaz de terminal
osintkit scan OBJETIVO         escaneo por perfil
osintkit scan -i               asistente de tipo de objetivo y perfil
osintkit run HERRAMIENTA OBJ   ejecuta una sola capacidad
osintkit list [texto]          catálogo filtrable
osintkit search TEXTO          busca por nombre, etiqueta o descripción
osintkit show ID               detalle, claves y binarios de una herramienta
osintkit profiles              perfiles de escaneo
osintkit catalog               catálogo completo (--markdown RUTA, --json)
osintkit doctor [-v]           diagnóstico de dependencias, claves y red
osintkit install               comandos para instalar binarios faltantes
osintkit config ...            configuración y claves API
osintkit version               versión y estadísticas
```

Opciones útiles de `scan`:

```sh
osintkit scan example.com \
  --tools dns_records crtsh_subdomains http_probe \
  --format json,md,html \
  --report-dir ./informes \
  --concurrency 12 \
  --no-cache
```

`--format none` evita escribir informes. `--dry-run` muestra qué se ejecutaría
sin hacer ninguna consulta.

---

## Informes

El informe también se muestra en la propia terminal al terminar el escaneo
(resumen, estado por herramienta y hallazgos). Cada escaneo genera, por defecto,
tres archivos en `$XDG_DATA_HOME/osintkit/reports` (normalmente
`~/.local/share/osintkit/reports`):

- `*.json`: resultado completo y estructurado.
- `*.md`: informe legible para revisión o pegado en un ticket.
- `*.html`: informe autocontenido con estilos, sin JavaScript ni recursos
  externos.

El HTML escapa todo el contenido y puede abrirse offline. Los informes incluyen
resumen, estado por herramienta, errores, omisiones y hallazgos con nivel
(`info`, `good`, `warn`, `bad`, `link`).

---

## Claves API

Todo funciona sin claves, pero algunos servicios mejoran o requieren una clave.
Se leen primero del **entorno** y después del archivo de configuración:

```sh
export SHODAN_API_KEY="..."
export VIRUSTOTAL_API_KEY="..."
osintkit doctor -v
```

Guardar en configuración (permisos `600`):

```sh
osintkit config set-key SHODAN_API_KEY "..."
osintkit config set-key ABUSECH_AUTH_KEY "..."
osintkit config show
osintkit config unset-key SHODAN_API_KEY
```

| Clave | Servicio |
|---|---|
| `VIRUSTOTAL_API_KEY` | VirusTotal |
| `SHODAN_API_KEY` | Shodan |
| `CENSYS_API_ID`, `CENSYS_API_SECRET` | Censys |
| `HIBP_API_KEY` | Have I Been Pwned |
| `ABUSECH_AUTH_KEY` | URLhaus, MalwareBazaar, ThreatFox |
| `ABUSEIPDB_API_KEY` | AbuseIPDB |
| `GREYNOISE_API_KEY` | GreyNoise |
| `HUNTER_API_KEY` | Hunter.io |
| `EMAILREP_API_KEY` | EmailRep |
| `NUMVERIFY_API_KEY` | Numverify |
| `VERIPHONE_API_KEY` | Veriphone |
| `ABSTRACT_PHONE_API_KEY` | Abstract Phone |
| `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` | Twilio Lookup |
| `IPQUALITYSCORE_API_KEY` | IPQualityScore |
| `OPENCORPORATES_API_KEY` | OpenCorporates |
| `COMPANIES_HOUSE_API_KEY` | Companies House (UK) |
| `OPENSANCTIONS_API_KEY` | OpenSanctions |
| `GITHUB_TOKEN` | GitHub (más límite de API) |
| `NVD_API_KEY` | NVD (opcional) |
| `TWITCH_CLIENT_ID`, `TWITCH_CLIENT_SECRET` | Twitch |
| `STEAM_API_KEY` | Steam |
| `SEC_API_KEY` | SEC EDGAR (opcional) |

Rutas XDG:

- Configuración: `~/.config/osintkit/config.json`
- Datos e informes: `~/.local/share/osintkit/`
- Caché HTTP: `~/.cache/osintkit/`

Personaliza el archivo con `osintkit config set NOMBRE VALOR`, por ejemplo:

```sh
osintkit config set concurrency 12
osintkit config set timeout 20
osintkit config set username_mass_limit 2000
osintkit config set username_mass_workers 40
osintkit config set username_mass_timeout 6
osintkit config set email_mass_limit 2000
osintkit config set email_mass_workers 40
osintkit config set email_mass_timeout 6
osintkit config set report_dir ~/informes/osint
osintkit config set color false
```

---

## Herramientas externas opcionales

osintkit detecta binarios en `PATH` y omite con un aviso claro lo que falte.
Para ver qué instalar:

```sh
osintkit install
osintkit doctor -v
```

En Void Linux, muchos paquetes están en el repositorio oficial; otros se
instalan con `go install` o `pipx`:

```sh
sudo xbps-install -S nmap whois bind-utils exiftool jq curl openssl
sudo xbps-install -S go python3-pipx
pipx install theHarvester
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

El catálogo incluye sugerencias por herramienta (`osintkit show ID`). Los
módulos internos no necesitan nada de esto.

---

## Plugins

Crea `~/.config/osintkit/plugins/miplugin.py`:

```python
from osintkit.catalog import Tool
from osintkit.core import Finding
from osintkit.modules.base import f


def register(api):
    api.tool(Tool(
        id="mi_fuente",
        name="Mi fuente",
        category="search",
        kinds=("domain", "keyword"),
        description="Consulta una API propia.",
        module="mi_fuente",
        passive=True,
    ))

    @api.module("mi_fuente")
    def mi_fuente(ctx, tool):
        # ctx.http.get(...), ctx.key("MI_API_KEY"), ctx.target
        return [f("Hola", ctx.target, "info")]
```

Arranca de nuevo y aparecerá en el catálogo, la CLI y la TUI. Un error en un
plugin no impide usar el resto de la aplicación.

---

## Arquitectura

```text
osintkit/
├── bin/osintkit              lanzador de desarrollo
├── bin/osintol               alias de desarrollo (abre la misma TUI/CLI)
├── THIRD_PARTY_NOTICES.md    atribución de datos de Maigret
├── osintkit/
│   ├── cli.py                argumentos y comandos
│   ├── ui.py                 interfaz curses
│   ├── catalog.py            catálogo, perfiles y validación
│   ├── core.py               registro, contexto y ejecución concurrente
│   ├── datasets.py           carga de bases internas
│   ├── http.py               cliente HTTP con caché, reintentos y rate limit
│   ├── config.py             configuración XDG y claves
│   ├── ports.py              nombres de puertos y etiquetado de servicios
│   ├── report.py             informes JSON / Markdown / HTML
│   ├── summary.py            resumen final de IPs y enlaces
│   ├── util.py               detección, hashes y helpers
│   ├── modules/              módulos internos por dominio
│   │   ├── username_mass.py  enumeración en 2.000+ sitios
│   │   └── email_mass.py     Gmail/email mediante la parte local
│   └── data/                 username_sites.json, phone_sources.json
├── docs/TOOLS.md             catálogo generado
├── tests/                    pruebas unittest
└── pyproject.toml
```

Flujo de un escaneo:

1. Se detecta el tipo de objetivo y se resuelve el perfil.
2. Se filtran herramientas pasivas/activas y se comprueban claves y binarios.
3. `run_scan` ejecuta en paralelo con un `HttpClient` compartido (caché,
   reintentos y límite de ritmo por host).
4. Cada módulo devuelve `Finding`; los binarios devuelven líneas de salida.
5. Se generan informes y se muestran en consola/TUI.

Los módulos internos usan solo `urllib`, `json`, `re`, `socket`, `ssl`,
`hashlib`, `struct` y otras bibliotecas estándar. No hay dependencias de red
obligatorias ni telemetría.

---

## Desarrollo y pruebas

```sh
python3 -m py_compile $(find osintkit -name '*.py')
python3 -m unittest discover -s tests -v

# regenerar el catálogo
./bin/osintkit catalog --markdown docs/TOOLS.md
```

Para depurar una excepción:

```sh
OSINTKIT_DEBUG=1 ./bin/osintkit scan example.com
```

La validación del catálogo comprueba IDs duplicados, categorías, tipos,
módulos referenciados y perfiles:

```sh
./bin/osintkit catalog --json > /dev/null && echo catálogo OK
```

---

## Limitaciones conocidas

- Las APIs públicas cambian, limitan o bloquean consultas sin aviso. Algunos
  módulos devuelven un enlace de búsqueda manual cuando no pueden resolver un
  perfil directo; ese enlace aparece etiquetado como tal.
- Sin claves API hay límites bajos (VirusTotal, Shodan, HIBP, abuse.ch…).
- Reddit bloquea con frecuencia las consultas anónimas desde centros de datos.
- Los datos de RDAP/WHOIS pueden estar redactados por privacidad.
- `theHarvester`, `spiderfoot` y escáneres activos pueden tardar minutos.
- La TUI requiere una terminal interactiva; en entornos no interactivos usa la
  CLI.
- Este proyecto no sustituye el juicio de un analista: verifica siempre los
  hallazgos en las fuentes originales.

---

## Licencia

MIT. Consulta el archivo `LICENSE` si está incluido en la distribución.
