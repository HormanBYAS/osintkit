# Catálogo de herramientas

Total: **303** herramientas en **13** categorías.

## DNS y dominios

_Registros, subdominios, certificados y WHOIS_

| Herramienta | Tipos | Modo | Requiere | Descripción |
|---|---|---|---|---|
| `dns_records` | domain, url | módulo | — | Consulta A, AAAA, MX, NS, TXT, SOA, CNAME y CAA vía DNS-over-HTTPS. |
| `dns_email_security` | domain | módulo | — | Revisa políticas de correo, selectores DKIM comunes y errores de configuración. |
| `dns_dnssec` | domain | módulo | — | Comprueba si la zona está firmada y si el resolutor valida DNSSEC (AD). |
| `whois_domain` | domain | módulo | — | Registrador, fechas, estados, nameservers y contactos vía RDAP o whois. |
| `crtsh_subdomains` | domain | módulo | — | Extrae nombres de Certificate Transparency. Excelente fuente pasiva. |
| `crtsh_certificates` | domain | módulo | — | Emisores, validez y SANs de certificados históricos del dominio. |
| `hackertarget_hostsearch` | domain | módulo | — | Búsqueda pasiva de hosts y subdominios en la API pública de HackerTarget. |
| `otx_passive_dns` | domain | módulo | — | Registros DNS históricos vistos por AlienVault OTX. |
| `commoncrawl_index` | domain | módulo | — | URLs del dominio en el índice más reciente de Common Crawl. |
| `subfinder` | domain | binario | bin `subfinder` | Enumeración pasiva de subdominios con decenas de fuentes. |
| `amass` | domain | binario | bin `amass` | Enumeración de superficie de ataque y DNS pasivo de OWASP. |
| `assetfinder` | domain | binario | bin `assetfinder` | Subdominios y dominios relacionados a partir de fuentes públicas. |
| `findomain` | domain | binario | bin `findomain` | Enumerador de subdominios rápido y multiplataforma. |
| `dnsx` | domain | binario | bin `dnsx` | Resolución y sondeo DNS masivo de ProjectDiscovery. |
| `dnsrecon` | domain | binario | bin `dnsrecon` | Enumeración DNS clásica: zona, fuerza bruta y registros. |
| `dnsenum` | domain | binario | bin `dnsenum` | Enumeración DNS y búsqueda de transferencias de zona. |
| `fierce` | domain | binario | bin `fierce` | Reconocimiento DNS de dominios y rangos cercanos. |
| `slurp` | domain | binario | bin `slurp` | Descubre subdominios desde certificados y los evalúa. |
| `cloud_enum` | domain | binario | bin `cloud_enum` | Busca buckets y recursos cloud con el nombre de la organización. |
| `dnsdumpster` | domain | web | — | Mapa visual de hosts y DNS (consulta web). |
| `securitytrails` | domain, ip | web | — | Inteligencia DNS histórica y WHOIS (requiere cuenta). |
| `viewdns_reverse_whois` | domain, email | web | — | Dominios relacionados por email, organización o registrante. |
| `mxtoolbox` | domain | web | — | Chequeos de DNS, MX, SPF, DMARC y listas negras. |
| `intodns` | domain | web | — | Diagnóstico completo de configuración DNS y correo. |
| `dnschecker` | domain | web | — | Propagación de registros DNS en resolutores del mundo. |
| `whois_web` | domain, ip | web | — | Consulta WHOIS web cuando RDAP no responde. |
| `whoxy` | domain, email | web | — | WHOIS histórico y reverse WHOIS. |
| `domaintools` | domain, ip | web | — | WHOIS histórico y reputación (cuenta comercial). |
| `certspotter` | domain | web | — | Búsqueda de certificados y subdominios en Certificate Transparency. |
| `sslmate` | domain | web | — | Buscador de certificados emitidos para un dominio. |
| `crtsh_web` | domain | web | — | Interfaz web de Certificate Transparency. |
| `theharvester` | domain, org | binario | bin `theHarvester` | Emails, hosts, empleados y nombres desde fuentes públicas. |
| `spiderfoot` | domain, ip, email, username | binario | bin `spiderfoot` | Automatización de OSINT con más de 200 módulos. |
| `puredns` | domain | binario | bin `puredns` | Resolución masiva de subdominios con validación y wildcard filtering. |
| `dnsgen` | domain | binario | bin `dnsgen` | Genera permutaciones de subdominios a partir de una lista. |

## Web y superficie

_HTTP, TLS, tecnologías, rutas y archivado_

| Herramienta | Tipos | Modo | Requiere | Descripción |
|---|---|---|---|---|
| `http_probe` | domain, url | módulo | — | Estado, redirecciones, cabeceras, título, cookies e IP de destino. |
| `tls_certificate` | domain, url | módulo | — | Sujeto, emisor, SANs, algoritmo y vencimiento del certificado. |
| `robots_txt` | domain, url | módulo | — | Rutas y directorios declarados en robots.txt. |
| `sitemap_xml` | domain, url | módulo | — | URLs y sub-sitemaps declarados por el sitio. |
| `security_txt` | domain, url | módulo | — | Contacto de seguridad y divulgación responsable. |
| `web_tech` | domain, url | módulo | — | Huella de servidor, frameworks, CMS, analytics y cabeceras. |
| `subdomain_takeover` | domain | módulo | — | Detecta CNAMEs que apuntan a servicios abandonados o secuestrables. |
| `urlscan_search` | domain, url, ip | módulo | — | Escaneos públicos, recursos, IPs y tecnologías observadas. |
| `wayback_availability` | domain, url | módulo | — | Última captura disponible y estado del archivo. |
| `wayback_cdx` | domain, url | módulo | — | URLs históricas y estados archivados por el Internet Archive. |
| `urlhaus_host` | domain, ip | módulo | key `ABUSECH_AUTH_KEY` | Hosts asociados a distribución de malware (abuse.ch). |
| `google_dorks_domain` | domain, email, username, org | módulo | — | Genera dorks de indexación, archivos expuestos y credenciales. |
| `httpx` | domain, url | binario | bin `httpx` | Sondeo HTTP masivo con título, tecnologías y códigos de estado. |
| `nuclei` | domain, url | binario | bin `nuclei` | Escaneo con plantillas de vulnerabilidades conocidas. Activo. |
| `naabu` | domain, ip | binario | bin `naabu` | Descubrimiento de puertos TCP rápido. Activo. |
| `katana` | domain, url | binario | bin `katana` | Crawler de nueva generación para descubrir rutas y endpoints. |
| `gau` | domain, url | binario | bin `gau` | URLs conocidas desde AlienVault, Wayback y Common Crawl. |
| `waybackurls` | domain, url | binario | bin `waybackurls` | URLs históricas de Wayback Machine. |
| `waymore` | domain, url | binario | bin `waymore` | Recolector de URLs desde Wayback, Common Crawl y más. |
| `whatweb` | domain, url | binario | bin `whatweb` | Fingerprinting de CMS, servidores y frameworks. |
| `wafw00f` | domain, url | binario | bin `wafw00f` | Identifica WAFs y protecciones perimetrales. |
| `nikto` | domain, url | binario | bin `nikto` | Escáner de configuraciones y archivos peligrosos. Activo. |
| `wpscan` | domain, url | binario | bin `wpscan` | Enumeración y vulnerabilidades de WordPress. Activo. |
| `cmseek` | domain, url | binario | bin `cmseek` | Detección y enumeración de CMS. |
| `joomscan` | domain, url | binario | bin `joomscan` | Escaneo específico de Joomla. |
| `droopescan` | domain, url | binario | bin `droopescan` | Escaneo de Drupal, WordPress, SilverStripe y otros CMS. |
| `gobuster` | domain, url | binario | bin `gobuster` | Fuerza bruta de directorios y subdominios. Activo. |
| `ffuf` | domain, url | binario | bin `ffuf` | Fuzzing web rápido para rutas, parámetros y vhosts. Activo. |
| `dirsearch` | domain, url | binario | bin `dirsearch` | Descubrimiento de rutas y archivos web. Activo. |
| `linkfinder` | domain, url | binario | bin `linkfinder`, bin `linkfinder.py` | Extrae endpoints y rutas desde JavaScript. |
| `xnlinkfinder` | domain, url | binario | bin `xnLinkFinder` | Búsqueda de enlaces, parámetros y secretos en JS. |
| `secretfinder` | domain, url | binario | bin `SecretFinder` | Busca API keys y secretos en archivos JavaScript. |
| `s3scanner` | domain, org | binario | bin `s3scanner` | Busca buckets S3 abiertos relacionados con el nombre. |
| `gcpbucketbrute` | domain, org | binario | bin `gcpbucketbrute.py` | Enumera buckets de Google Cloud Storage. |
| `testssl` | domain, ip, url | binario | bin `testssl.sh` | Auditoría completa de TLS/SSL y cifrados. |
| `sslscan` | domain, ip, url | binario | bin `sslscan` | Escaneo de configuración TLS y certificados. |
| `photon` | domain, url | binario | bin `photon` | Crawler OSINT que extrae URLs, emails, redes y secretos. |
| `gowitness` | domain, url | binario | bin `gowitness` | Capturas de pantalla de sitios para revisión visual. |
| `waybackpack` | domain, url | binario | bin `waybackpack` | Descarga el historial completo de un sitio desde Wayback. |
| `cloudbrute` | domain, org | binario | bin `cloudbrute` | Enumera infraestructura cloud por nombre de empresa. |
| `gobuster_vhost` | domain | binario | bin `gobuster` | Descubre hosts virtuales en un servidor web. Activo. |
| `dalfox` | url | binario | bin `dalfox` | Escáner de XSS. Activo; úsalo solo con autorización. |

## IP y red

_Geolocalización, ASN, reputación y puertos_

| Herramienta | Tipos | Modo | Requiere | Descripción |
|---|---|---|---|---|
| `ip_geo` | ip, domain | módulo | — | País, ciudad, ISP, ASN y coordenadas aproximadas. |
| `ip_asn` | ip, domain | módulo | — | Sistema autónomo, prefijo anunciado y organización. |
| `ip_rdap` | ip | módulo | — | Rango, organización, país y contactos de una dirección IP. |
| `reverse_dns` | ip | módulo | — | Nombre canónico asociado a una IP. |
| `shodan_internetdb` | ip, domain | módulo | — | Puertos, hostnames, CPEs y CVEs observados sin necesidad de clave. |
| `tor_exit` | ip | módulo | — | Comprueba si la IP figura en la lista oficial de exit nodes. |
| `dnsbl` | ip | módulo | — | Consulta listas negras DNS de spam y reputación. |
| `ip_bgp_prefixes` | ip | módulo | — | Prefijo anunciado, origen y visibilidad en RIPEstat. |
| `otx_indicator` | ip, domain, hash, url | módulo | — | Pulsos y reputación de AlienVault OTX para un IOC. |
| `virustotal_ip` | ip | módulo | key `VIRUSTOTAL_API_KEY` | Reputación, resoluciones DNS y detecciones de una IP. |
| `virustotal_domain` | domain | módulo | key `VIRUSTOTAL_API_KEY` | Reputación, subdominios y categorías de un dominio. |
| `virustotal_url` | url | módulo | key `VIRUSTOTAL_API_KEY` | Análisis de una URL concreta en VirusTotal. |
| `abuseipdb` | ip | módulo | key `ABUSEIPDB_API_KEY` | Reportes de abuso, país y uso de la IP. |
| `greynoise` | ip | módulo | key `GREYNOISE_API_KEY` | Clasifica si una IP es ruido de internet o un actor dirigido. |
| `shodan_host` | ip | módulo | key `SHODAN_API_KEY` | Puertos, banners, vulns y hostnames de Shodan. |
| `censys_ip` | ip | módulo | key `CENSYS_API_ID`, key `CENSYS_API_SECRET` | Servicios y certificados observados por Censys. |
| `nmap` | ip, domain | binario | bin `nmap` | Descubrimiento de puertos y servicios. Activo y ruidoso. |
| `masscan` | ip, domain | binario | bin `masscan` | Escaneo de puertos a gran velocidad. Activo. |
| `traceroute` | ip, domain | binario | bin `traceroute` | Ruta de red hasta el objetivo. |
| `ping` | ip, domain | binario | bin `ping` | Comprobación de alcance ICMP. |
| `shodan_cli` | ip, domain | binario | key `SHODAN_API_KEY`, bin `shodan` | Consulta Shodan desde la terminal (requiere init). |
| `censys_cli` | ip, domain | binario | key `CENSYS_API_ID`, key `CENSYS_API_SECRET`, bin `censys` | Búsqueda de hosts y certificados desde Censys. |
| `whois_cli` | ip, domain | binario | bin `whois` | Cliente WHOIS clásico; útil cuando RDAP falla. |
| `ipinfo_web` | ip | web | — | Ficha web de IP con ASN, rango y geolocalización. |
| `ipapi_web` | ip | web | — | Geolocalización y datos de red de una IP. |
| `bgp_he` | ip, domain | web | — | Looking glass, ASN y prefijos de Hurricane Electric. |
| `ripestat_web` | ip | web | — | Estadísticas de enrutamiento y prefijos de RIPE NCC. |
| `criminalip` | ip, domain | web | — | Motor de búsqueda de exposición y amenazas (cuenta). |
| `zoomeye` | ip, domain | web | — | Buscador de dispositivos y servicios expuestos (cuenta). |
| `fofa` | ip, domain | web | — | Motor de búsqueda de activos de Internet (cuenta). |
| `netlas` | ip, domain | web | — | Búsqueda de hosts, certificados y servicios (cuenta). |
| `whatismyipaddress` | ip | web | — | Información y reputación de una IP. |

## Email

_Validación, perfiles, brechas, PGP y 2.000+ sitios_

| Herramienta | Tipos | Modo | Requiere | Descripción |
|---|---|---|---|---|
| `email_validate` | email | módulo | — | Sintaxis, MX, dominio desechable, cuentas de rol y señales de entrega. |
| `email_gravatar` | email | módulo | — | Comprueba si el hash del email tiene perfil o avatar público. |
| `email_pgp` | email | módulo | — | Busca una clave OpenPGP publicada para el email. |
| `email_hibp` | email | módulo | key `HIBP_API_KEY` | Brechas conocidas asociadas al email (API key). |
| `email_hunter` | email, domain | módulo | key `HUNTER_API_KEY` | Verificación y fuentes públicas del email (API key). |
| `emailrep` | email | módulo | key `EMAILREP_API_KEY` | Reputación y perfiles sociales asociados (API key). |
| `email_dork` | email | módulo | — | Busca el email y devuelve enlaces directos a perfiles y menciones. |
| `email_mass` | email | módulo | — | Comprueba la parte local del email en más de 2.600 sitios (Maigret, MIT). |
| `holehe` | email | binario | bin `holehe` | Comprueba en qué servicios está registrado un email. |
| `ghunt` | email | binario | bin `ghunt` | OSINT de cuentas Google a partir del email. |
| `h8mail` | email | binario | bin `h8mail` | Búsqueda de credenciales filtradas por email. |
| `mosint` | email | binario | bin `mosint` | Automatiza email OSINT y verificación de filtraciones. |
| `epieos` | email, phone | web | — | Consultas de cuentas Google, email y teléfono (web). |
| `hunter_web` | domain | web | — | Patrones de email y empleados públicos de un dominio. |
| `hibp_web` | email | web | — | Consulta manual de brechas por email. |
| `firefox_monitor` | email | web | — | Monitoreo de brechas de Mozilla. |
| `dehashed` | email, username, domain, ip | web | — | Buscador de filtraciones con API paga. |
| `leakcheck` | email, username, domain | web | — | Búsqueda de credenciales filtradas. |
| `intelx` | email, username, domain, ip | web | — | Buscador de filtraciones, pastebins y dark web. |
| `snusbase` | email, username, domain | web | — | Consultas de bases filtradas (cuenta). |
| `infoga` | domain, email | binario | bin `infoga` | Recopila emails y metadatos de un dominio. |
| `pwnedornot` | email | binario | bin `pwnedornot` | Busca contraseñas filtradas de un email. |

## Usuarios y redes

_Presencia de un alias en múltiples plataformas_

| Herramienta | Tipos | Modo | Requiere | Descripción |
|---|---|---|---|---|
| `username_presence` | username | módulo | — | Comprueba el alias en más de 35 servicios con detección de falsos positivos. |
| `username_mass` | username | módulo | — | Comprueba el alias en más de 2.600 sitios de la base interna (Maigret, MIT). |
| `username_github` | username | módulo | — | Perfil, repositorios, lenguajes, seguidores y actividad pública. |
| `username_gitlab` | username | módulo | — | Perfil público y proyectos en GitLab.com. |
| `username_reddit` | username | módulo | — | Karma, antigüedad y actividad pública. |
| `username_keybase` | username | módulo | — | Identidades vinculadas: GitHub, Twitter, dominios y claves. |
| `username_hackernews` | username | módulo | — | Karma, fecha de alta y comentarios públicos. |
| `username_mastodon` | username | módulo | — | Cuentas con ese alias en mastodon.social. |
| `username_telegram` | username | módulo | — | Existencia pública del alias y metadatos de la página t.me. |
| `username_pypi` | username | módulo | — | Perfil público de PyPI. |
| `username_npm` | username | módulo | — | Perfil público del registro npm. |
| `username_dockerhub` | username | módulo | — | Perfil y cantidad de repositorios públicos. |
| `username_stackoverflow` | username | módulo | — | Reputación, insignias y perfil público. |
| `username_twitch` | username | módulo | key `TWITCH_CLIENT_ID`, key `TWITCH_CLIENT_SECRET` | Canal y seguidores (requiere credenciales de API). |
| `username_steam` | username | módulo | key `STEAM_API_KEY` | Perfil público de Steam (API key). |
| `sherlock` | username | binario | bin `sherlock` | Búsqueda del alias en cientos de sitios. |
| `maigret` | username | binario | bin `maigret` | Enumeración de cuentas y generación de reportes. |
| `social_analyzer` | username | binario | bin `social-analyzer` | Análisis de perfiles en múltiples redes sociales. |
| `blackbird` | username, email | binario | bin `blackbird` | Búsqueda de cuentas por usuario o email. |
| `whatsmyname` | username | web | — | Proyecto colaborativo de enumeración de usuarios (web). |
| `instantusername` | username | web | — | Disponibilidad del alias en redes populares. |
| `namechk` | username | web | — | Disponibilidad de usuario y dominio. |
| `checkusernames` | username | web | — | Comprueba el alias en 160 redes. |
| `usersearch` | username | web | — | Búsqueda de alias en redes y foros. |
| `osrframework` | username, email | binario | bin `osrf` | Suite de usuario, email y búsquedas en redes. |

## Teléfono

_País, formato, reputación y perfiles directos_

| Herramienta | Tipos | Modo | Requiere | Descripción |
|---|---|---|---|---|
| `phone_info` | phone | módulo | — | Normaliza a E.164, detecta país y tipo de línea (con libphonenumber si está). |
| `phone_dork` | phone | módulo | — | Busca el número y devuelve enlaces directos a perfiles y menciones. |
| `phone_sources` | phone | módulo | — | Genera enlaces a 70 directorios, buscadores inversos y fuentes de reputación. |
| `phone_veriphone` | phone | módulo | key `VERIPHONE_API_KEY` | Valida el número y devuelve país, operador y tipo de línea (API key). |
| `phone_abstract` | phone | módulo | key `ABSTRACT_PHONE_API_KEY` | Validación y datos del número con Abstract API (API key). |
| `phone_twilio` | phone | módulo | key `TWILIO_ACCOUNT_SID`, key `TWILIO_AUTH_TOKEN` | Operador, tipo de línea y nombre del titular con Twilio (credenciales). |
| `phone_numverify` | phone | módulo | key `NUMVERIFY_API_KEY` | Validación, operador y tipo de línea (API key). |
| `phone_ipqualityscore` | phone | módulo | key `IPQUALITYSCORE_API_KEY` | Reputación y fraude telefónico (API key). |
| `phoneinfoga` | phone | binario | bin `phoneinfoga` | Reconocimiento de números: país, operador y fuentes. |
| `truecaller` | phone | web | — | Identificación colaborativa de números (web). |
| `sync_me` | phone | web | — | Identificación de llamadas (web). |
| `phone_src_whitepages` | phone | web | — | Búsqueda inversa y datos de contacto en EE. UU. |
| `phone_src_spokeo` | phone | web | — | Búsqueda inversa con perfiles sociales y datos públicos. |
| `phone_src_zabasearch` | phone | web | — | Directorio inverso de teléfonos y direcciones de EE. UU. |
| `phone_src_anywho` | phone | web | — | Directorio telefónico y búsqueda inversa. |
| `phone_src_411` | phone | web | — | Guía telefónica y búsqueda inversa de EE. UU. |
| `phone_src_usphonebook` | phone | web | — | Guía telefónica con nombres y ubicaciones. |
| `phone_src_reversephonelookup` | phone | web | — | Búsqueda inversa y reportes de llamadas. |
| `phone_src_phoneowner` | phone | web | — | Información del propietario y ubicación aproximada. |
| `phone_src_whocalld` | phone | web | — | Reportes comunitarios de llamadas y spam. |
| `phone_src_unknownphone` | phone | web | — | Comentarios y reportes de números desconocidos. |
| `phone_src_should_i_answer` | phone | web | — | Reputación comunitaria y tipo de llamada. |
| `phone_src_whocallsme` | phone | web | — | Foro de reportes de llamadas no deseadas. |
| `phone_src_tellows` | phone | web | — | Puntuación de spam y comentarios por número. |
| `phone_src_spamcalls_net` | phone | web | — | Base de datos colaborativa de llamadas spam. |
| `phone_src_callercenter` | phone | web | — | Reportes de llamadas y números fraudulentos. |
| `phone_src_numberway` | phone | web | — | Directorio telefónico internacional por país. |
| `phone_src_numlookup` | phone | web | — | Búsqueda inversa y datos del operador. |
| `phone_src_callersmart` | phone | web | — | Identificación colaborativa de llamadas. |
| `phone_src_peoplefinders` | phone | web | — | Búsqueda de personas por teléfono. |
| `phone_src_truthfinder` | phone | web | — | Búsqueda de personas y antecedentes públicos. |
| `phone_src_beenverified` | phone | web | — | Búsqueda inversa con datos públicos. |
| `phone_src_intelius` | phone | web | — | Búsqueda de personas por número. |
| `phone_src_instant_checkmate` | phone | web | — | Búsqueda de antecedentes y contactos. |
| `phone_src_infotracer` | phone | web | — | Búsqueda inversa y registros públicos. |
| `phone_src_searchpeoplefree` | phone | web | — | Búsqueda gratuita de personas y teléfonos. |
| `phone_src_fastpeoplesearch` | phone | web | — | Búsqueda rápida de personas y direcciones. |
| `phone_src_cyber_background_checks` | phone | web | — | Registros públicos y búsqueda inversa. |
| `phone_src_nuwber` | phone | web | — | Perfiles de personas y datos de contacto. |
| `phone_src_truepeoplesearch` | phone | web | — | Búsqueda gratuita de personas por teléfono. |
| `phone_src_addresses_com` | phone | web | — | Directorio de direcciones y teléfonos. |
| `phone_src_phonenumberlookup` | phone | web | — | Búsqueda de números y nombres asociados. |
| `phone_src_phonelookup` | phone | web | — | Consulta de número, operador y ubicación. |
| `phone_src_whocalled` | phone | web | — | Reportes de llamadas y números desconocidos. |
| `phone_src_scamcallfighters` | phone | web | — | Base de datos de llamadas fraudulentas. |
| `phone_src_phone_scams` | phone | web | — | Reportes y artículos sobre estafas telefónicas. |
| `phone_src_scam_numbers` | phone | web | — | Números reportados por la comunidad. |
| `phone_src_reverse_australia` | phone | web | — | Búsqueda inversa de teléfonos australianos. |
| `phone_src_white_pages_australia` | phone | web | — | Guía telefónica residencial de Australia. |
| `phone_src_canada411` | phone | web | — | Guía telefónica canadiense. |
| `phone_src_yellowpages_canada` | phone | web | — | Directorio de empresas y teléfonos de Canadá. |
| `phone_src_pagesjaunes` | phone | web | — | Directorio telefónico francés. |
| `phone_src_das_telefonbuch` | phone | web | — | Guía telefónica alemana. |
| `phone_src_11880` | phone | web | — | Directorio y búsqueda inversa alemana. |
| `phone_src_hitta_se` | phone | web | — | Directorio sueco de personas y empresas. |
| `phone_src_eniro` | phone | web | — | Guía telefónica y mapas de Suecia. |
| `phone_src_1881_no` | phone | web | — | Directorio telefónico noruego. |
| `phone_src_gulesider` | phone | web | — | Guía telefónica y mapas de Noruega. |
| `phone_src_krak` | phone | web | — | Directorio telefónico danés. |
| `phone_src_telefoonboek` | phone | web | — | Guía telefónica neerlandesa. |
| `phone_src_fonecta` | phone | web | — | Directorio telefónico finlandés. |
| `phone_src_paginasamarillas` | phone | web | — | Páginas amarillas de España. |
| `phone_src_qdq` | phone | web | — | Directorio de teléfonos y empresas de España. |
| `phone_src_infobel` | phone | web | — | Directorio telefónico internacional. |
| `phone_src_white_pages_nz` | phone | web | — | Guía telefónica de Nueva Zelanda. |
| `phone_src_telelistas` | phone | web | — | Guía telefónica brasileña. |
| `phone_src_118000` | phone | web | — | Búsqueda inversa y directorio francés. |
| `phone_src_annuaire` | phone | web | — | Anuario telefónico francés. |
| `phone_src_telefoonboek_belgi` | phone | web | — | Guía telefónica belga. |
| `phone_src_herold_at` | phone | web | — | Directorio telefónico austríaco. |
| `phone_src_search_ch` | phone | web | — | Guía telefónica suiza. |
| `phone_src_local_ch` | phone | web | — | Directorio local y telefonía suiza. |
| `phone_src_golden_pages_ireland` | phone | web | — | Páginas amarillas de Irlanda. |
| `phone_src_yell_uk` | phone | web | — | Directorio de empresas del Reino Unido. |
| `phone_src_192_com` | phone | web | — | Búsqueda de personas y teléfonos del Reino Unido. |
| `phone_src_justdial` | phone | web | — | Directorio de empresas y servicios de India. |
| `phone_src_yellow_pages_uae` | phone | web | — | Páginas amarillas de Emiratos Árabes Unidos. |
| `phone_src_epieos_phone` | phone | web | — | Comprueba si el número está asociado a una cuenta Google. |
| `phone_src_whatsapp` | phone | web | — | Abre un chat directo; no verifica la cuenta sin iniciar sesión. |
| `phone_src_telegram` | phone | web | — | Intenta abrir un chat o invitación de Telegram. |
| `phone_src_signal` | phone | web | — | Abre el perfil de Signal si el número está registrado. |

## Criptomonedas

_Direcciones BTC/ETH y actividad on-chain_

| Herramienta | Tipos | Modo | Requiere | Descripción |
|---|---|---|---|---|
| `btc_address` | crypto | módulo | — | Saldo, transacciones y primera/última actividad on-chain. |
| `eth_address` | crypto | módulo | — | Saldo y actividad de una cuenta Ethereum (API key opcional). |
| `crypto_other` | crypto | módulo | — | Consulta LTC, DOGE, XMR y otras redes en exploradores públicos. |
| `chainabuse` | crypto | web | — | Reportes de fraude asociados a una dirección (web). |
| `blockchair_web` | crypto | web | — | Explorador multi-cadena con búsqueda por dirección. |

## Organizaciones

_Registros mercantiles, sanciones y datos abiertos_

| Herramienta | Tipos | Modo | Requiere | Descripción |
|---|---|---|---|---|
| `wikidata_search` | org, keyword, domain, username | módulo | — | Entidades, identificadores y enlaces oficiales. |
| `wikipedia_search` | org, keyword, domain, username | módulo | — | Artículos y menciones enciclopédicas. |
| `gleif_lei` | org | módulo | — | Identificador legal de entidades financieras y socios. |
| `sec_edgar` | org | módulo | — | Presentaciones corporativas de empresas que cotizan en EE. UU. |
| `opensanctions` | org, username | módulo | — | Sanciones, PEPs y entidades de riesgo. |
| `opencorporates` | org | módulo | key `OPENCORPORATES_API_KEY` | Registros mercantiles de todo el mundo (API key). |
| `companies_house` | org | módulo | key `COMPANIES_HOUSE_API_KEY` | Empresas, directores y cuentas del Reino Unido (API key). |
| `aleph_occrp` | org, username | web | — | Filtraciones, registros y periodismo de investigación (web). |
| `offshore_leaks` | org | web | — | Base de datos de entidades offshore del ICIJ (web). |

## Amenazas

_CVEs, malware, IOC y reputación_

| Herramienta | Tipos | Modo | Requiere | Descripción |
|---|---|---|---|---|
| `nvd_search` | keyword, domain, ip | módulo | — | Búsqueda de vulnerabilidades en el catálogo del NIST. |
| `circl_cve` | keyword, hash | módulo | — | Ficha CVE con CVSS, referencias y productos afectados. |
| `epss_score` | keyword | módulo | — | Probabilidad de explotación de una CVE (FIRST.org). |
| `urlhaus_url` | url, domain | módulo | key `ABUSECH_AUTH_KEY` | URLs maliciosas y payloads asociados (abuse.ch). |
| `malwarebazaar` | hash, file | módulo | key `ABUSECH_AUTH_KEY` | Muestras de malware por hash (abuse.ch). |
| `threatfox` | ip, domain, hash, url | módulo | key `ABUSECH_AUTH_KEY` | IOCs y familias de malware (abuse.ch). |
| `feodo_tracker` | ip | módulo | — | Blocklist pública de infraestructura de botnets (abuse.ch). |
| `virustotal_hash` | hash | módulo | key `VIRUSTOTAL_API_KEY` | Detecciones y metadatos de un hash (API key). |
| `hybrid_analysis` | hash, file, url | web | — | Sandbox y análisis de malware (web). |
| `anyrun` | hash, file, url | web | — | Sandbox interactivo de malware (web). |
| `joesandbox` | hash, file, url | web | — | Análisis profundo de archivos y URLs (web). |
| `triage` | hash, file, url | web | — | Sandbox público de muestras (web). |
| `urlscan_web` | domain, url, ip | web | — | Búsqueda visual de escaneos y recursos (web). |
| `virustotal_web` | domain, ip, url, hash, file | web | — | Consulta manual de reputación en VirusTotal. |
| `otx_web` | domain, ip, url, hash | web | — | Pulsos y reputación de un indicador (web). |
| `abuseipdb_web` | ip | web | — | Reportes de abuso de una IP (web). |
| `greynoise_web` | ip | web | — | Contexto de ruido de internet para una IP (web). |
| `ransomwatch` | org, domain | web | — | Seguimiento de víctimas de ransomware (web). |
| `ransomware_live` | org, domain | web | — | Paneles y víctimas recientes de ransomware (web). |

## Búsqueda y dorks

_Motores, dorks y archivos históricos_

| Herramienta | Tipos | Modo | Requiere | Descripción |
|---|---|---|---|---|
| `ddg_search` | keyword, domain, email, username, org, phone, ip, url | módulo | — | Búsqueda web sin perfilado (HTML). |
| `github_search` | keyword, domain, email, username, org | módulo | — | Repositorios, usuarios y código público (token opcional). |
| `reddit_search` | keyword, domain, username | módulo | — | Posts y comentarios públicos. |
| `hn_search` | keyword, domain, username | módulo | — | Historias y comentarios indexados por Algolia. |
| `stackexchange_search` | keyword, username | módulo | — | Preguntas, respuestas y perfiles técnicos. |
| `archive_org_search` | keyword, domain, org, username | módulo | — | Textos, audio, video y colecciones archivadas. |
| `google_dorks_keyword` | keyword, domain, email, username, org, phone | módulo | — | Genera consultas avanzadas para Google, Bing y DuckDuckGo. |
| `startpage` | keyword | web | — | Búsqueda web con privacidad (web). |
| `yandex` | keyword, domain | web | — | Buscador con indexación distinta a Google (web). |
| `mojeek` | keyword | web | — | Buscador independiente con su propio índice (web). |
| `searx` | keyword | web | — | Metabuscador libre; elegí una instancia pública (web). |

## Archivos y metadatos

_Hashes, EXIF, PDF y secretos_

| Herramienta | Tipos | Modo | Requiere | Descripción |
|---|---|---|---|---|
| `file_hash` | file | módulo | — | MD5, SHA-1, SHA-256, SHA-512, tamaño y tipo probable. |
| `exif_metadata` | file | módulo | — | Cámara, fecha, software y GPS de imágenes JPEG/TIFF. |
| `pdf_info` | file | módulo | — | Título, autor, fechas, páginas y productor del PDF. |
| `strings_extract` | file | módulo | — | Extrae URLs, emails, IPs y claves embebidas en binarios. |
| `virustotal_file` | file | módulo | key `VIRUSTOTAL_API_KEY` | Sube el hash (no el archivo) y consulta detecciones. |
| `exiftool` | file | binario | bin `exiftool` | Extracción completa de metadatos de casi cualquier formato. |
| `metagoofil` | domain | binario | bin `metagoofil` | Descarga documentos públicos y extrae metadatos. |
| `trufflehog` | file, org | binario | bin `trufflehog` | Busca secretos y credenciales en repositorios o directorios. |
| `gitleaks` | file | binario | bin `gitleaks` | Detecta secretos en un directorio o repositorio local. |
| `binwalk` | file | binario | bin `binwalk` | Analiza firmas y archivos embebidos en firmware/binarios. |
| `foremost` | file | binario | bin `foremost` | Recupera archivos por firmas dentro de una imagen. |
| `file_cmd` | file | binario | bin `file` | Tipo real de archivo según sus firmas. |
| `pdfinfo` | file | binario | bin `pdfinfo` | Información técnica de un PDF. |

## Geolocalización

_Lugares, mapas y puntos de interés_

| Herramienta | Tipos | Modo | Requiere | Descripción |
|---|---|---|---|---|
| `nominatim` | org, keyword | módulo | — | Geocodificación de lugares y direcciones. |
| `overpass_poi` | org, keyword | módulo | — | Busca puntos de interés y comercios cerca de un lugar. |
| `google_maps` | org, keyword | web | — | Búsqueda de lugares y negocios (web). |
| `openstreetmap` | org, keyword | web | — | Mapa colaborativo abierto (web). |
| `yandex_maps` | org, keyword | web | — | Mapas y organizaciones (web). |

## Enlaces y directorios

_Recursos web de consulta manual_

| Herramienta | Tipos | Modo | Requiere | Descripción |
|---|---|---|---|---|
| `osint_framework` | keyword | web | — | Árbol navegable de recursos OSINT por tipo de objetivo. |
| `bellingcat_toolkit` | keyword | web | — | Herramientas y guías de investigación de Bellingcat. |
| `inteltechniques` | keyword | web | — | Índice clásico de herramientas OSINT de Michael Bazzell. |
| `osint_sh` | keyword | web | — | Colección de utilidades y buscadores OSINT. |

