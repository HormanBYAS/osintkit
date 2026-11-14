# Avisos de terceros

osintkit incluye datos derivados de proyectos de código abierto. Los datos se
distribuyen con sus licencias originales y se usan únicamente para enumerar
perfiles públicos. La base de sitios de usuario se emplea tanto para alias como
para la parte local de un email o Gmail.

## Maigret

- Proyecto: <https://github.com/soxoj/maigret>
- Archivo derivado: `osintkit/data/username_sites.json`
- Licencia: MIT
- Copyright: Copyright (c) 2020-2026 Soxoj

El archivo `username_sites.json` es una transformación del archivo
`maigret/resources/data.json` de Maigret: se eliminan entradas deshabilitadas,
se normalizan los campos y se conservan los marcadores de presencia/ausencia.
No se incluye código de Maigret.

Texto de la licencia MIT de Maigret:

```text
MIT License

Copyright (c) 2020-2026 Soxoj

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## Directorios de teléfono

`osintkit/data/phone_sources.json` es una lista propia de enlaces a servicios
públicos de consulta. Cada servicio mantiene sus propios términos de uso y
límites; osintkit no consulta automáticamente esos directorios, solo genera el
enlace para revisión manual.
