# Lizenzinformationen

Dieses Dokument listet alle externen Komponenten, Bibliotheken, Frameworks und Datenquellen auf, die in NetFlowMap verwendet werden, zusammen mit ihren Lizenzen und Quellen.

## Backend (Go)

### Direkte Abhängigkeiten

| Komponente | Version | Quelle | Lizenz | Verwendung |
|------------|---------|--------|--------|------------|
| **go-chi/chi** | v5.2.3 | https://github.com/go-chi/chi | MIT License | HTTP-Router und Middleware |
| **gorilla/websocket** | v1.5.3 | https://github.com/gorilla/websocket | BSD 2-Clause License | WebSocket-Kommunikation für Echtzeit-Updates |
| **coreos/go-oidc** | v3.17.0 | https://github.com/coreos/go-oidc | Apache License 2.0 | OpenID Connect Authentifizierung |
| **golang-jwt/jwt** | v5.3.0 | https://github.com/golang-jwt/jwt | MIT License | JWT-Token-Verarbeitung für Sessions |
| **oschwald/maxminddb-golang** | v1.13.1 | https://github.com/oschwald/maxminddb-golang | Apache License 2.0 | GeoIP-Datenbank-Reader (MaxMind DB Format) |
| **golang.org/x/crypto** | v0.46.0 | https://golang.org/x/crypto | BSD 3-Clause License | Kryptografische Funktionen (bcrypt für Passwort-Hashing) |
| **golang.org/x/oauth2** | v0.34.0 | https://golang.org/x/oauth2 | BSD 3-Clause License | OAuth2-Client für OIDC |
| **gopkg.in/yaml.v3** | v3.0.1 | https://github.com/go-yaml/yaml | Apache License 2.0 / MIT License | YAML-Konfigurationsparsing |

### Indirekte Abhängigkeiten

| Komponente | Version | Quelle | Lizenz | Verwendung |
|------------|---------|--------|--------|------------|
| **go-jose/go-jose** | v4.1.3 | https://github.com/go-jose/go-jose | MIT License | JOSE-Implementierung (indirekt über go-oidc) |
| **golang.org/x/sys** | v0.39.0 | https://golang.org/x/sys | BSD 3-Clause License | System-Calls (indirekt über andere Pakete) |

### Programmiersprache

| Komponente | Version | Quelle | Lizenz | Verwendung |
|------------|---------|--------|--------|------------|
| **Go** | 1.25.3 | https://golang.org/ | BSD 3-Clause License | Programmiersprache |

## Frontend (JavaScript/CSS)

### JavaScript-Bibliotheken

| Komponente | Version | Quelle | Lizenz | Verwendung |
|------------|---------|--------|--------|------------|
| **Leaflet** | 1.9.4 | https://leafletjs.com/ | BSD 2-Clause License | Interaktive Kartenvisualisierung |

### Karten-Tiles (Externe Services)

| Komponente | Version | Quelle | Lizenz | Verwendung |
|------------|---------|--------|--------|------------|
| **CARTO Basemaps** | - | https://carto.com/basemaps/ | OpenStreetMap ODbL + CARTO Basemaps Terms of Service | Karten-Tiles für die Dark-Map-Ansicht |
| **OpenStreetMap** | - | https://www.openstreetmap.org/ | Open Database License (ODbL) | Kartendatenquelle für CARTO Basemaps |

**Wichtiger Hinweis:** 
- CARTO Basemaps ist ein **externer Service** (keine Bibliothek), der zur Laufzeit über `cartocdn.com` aufgerufen wird
- Die Karten-Tiles werden **nicht als Teil des Codes weiterverbreitet**, sondern werden zur Laufzeit vom CARTO-Server geladen
- Die Attribution erfolgt automatisch im UI (siehe `web/static/js/app.js`)
- CARTO Basemaps verwendet OpenStreetMap-Daten und stellt diese als kostenlosen Tile-Service zur Verfügung
- **Nutzungsbedingungen:** Die spezifischen "Basemaps Terms of Service" von CARTO sollten direkt geprüft werden: https://carto.com/legal
- Da es sich um einen externen Service handelt, der zur Laufzeit aufgerufen wird, verhindert dies **nicht** die Weiterverbreitung des NetFlowMap-Codes unter einer Open-Source-Lizenz

### Schriftarten

| Komponente | Version | Quelle | Lizenz | Verwendung |
|------------|---------|--------|--------|------------|
| **JetBrains Mono** | - | https://fonts.google.com/specimen/JetBrains+Mono | SIL Open Font License 1.1 | Monospace-Schriftart für technische Informationen |
| **Space Grotesk** | - | https://fonts.google.com/specimen/Space+Grotesk | SIL Open Font License 1.1 | Hauptschriftart für UI-Elemente |

**Hinweis:** Die Schriftarten werden über Google Fonts CDN geladen.

## Datenbanken & Datenquellen

| Komponente | Version | Quelle | Lizenz | Verwendung |
|------------|---------|--------|--------|------------|
| **DB-IP Lite City** | Monatlich aktualisiert | https://db-ip.com/db/lite.php | Creative Commons Attribution 4.0 International (CC BY 4.0) | GeoIP-Standortdatenbank (Stadt, Land, Koordinaten) |
| **DB-IP Lite ASN** | Monatlich aktualisiert | https://db-ip.com/db/lite.php | Creative Commons Attribution 4.0 International (CC BY 4.0) | ASN-Datenbank (Autonomous System Number, Organisation) |

**Hinweis:** Beide Datenbanken werden automatisch von NetFlowMap heruntergeladen und monatlich aktualisiert. Die Datenbanken werden im MaxMind DB Format bereitgestellt.

## Build-Tools & Runtime

| Komponente | Version | Quelle | Lizenz | Verwendung |
|------------|---------|--------|--------|------------|
| **Alpine Linux** | 3.19 | https://alpinelinux.org/ | Apache License 2.0 | Basis-Image für Docker-Container |
| **golang:1.25-alpine** | - | https://hub.docker.com/_/golang | BSD 3-Clause License (Go) | Build-Container für Docker-Builds |

## Lizenz-Kompatibilität

Alle verwendeten Lizenzen sind kompatibel mit der MIT-Lizenz von NetFlowMap:

- **MIT License**: Mehrere Komponenten (go-chi, golang-jwt/jwt, go-jose)
- **Apache License 2.0**: Mehrere Komponenten (go-oidc, maxminddb-golang, yaml.v3, Alpine Linux)
- **BSD 2-Clause / BSD 3-Clause**: Go-Standard-Bibliotheken und Leaflet
- **SIL Open Font License 1.1**: Schriftarten (kompatibel mit MIT)
- **Creative Commons Attribution 4.0**: GeoIP-Datenbanken (CC BY 4.0 erfordert Attribution)
- **Open Database License (ODbL)**: OpenStreetMap-Daten (über CARTO Basemaps)
- **CARTO Basemaps**: Externer Service, keine Code-Weiterverbreitung erforderlich

**Wichtig:** CARTO Basemaps ist ein externer Service, der zur Laufzeit aufgerufen wird. Die Karten-Tiles werden nicht als Teil des Codes weiterverbreitet, daher verhindern die CARTO Terms of Service **nicht** die Weiterverbreitung des NetFlowMap-Codes unter einer Open-Source-Lizenz. Die Nutzungsbedingungen gelten für die Nutzung des Services zur Laufzeit, nicht für die Verteilung des Codes.

## Attribution-Anforderungen

### CC BY 4.0 (DB-IP Lite)
Die GeoIP-Datenbanken von DB-IP Lite stehen unter CC BY 4.0 und erfordern Attribution. Diese erfolgt implizit durch die Verwendung der Datenbanken im Projekt.

### OpenStreetMap (über CARTO Basemaps)
Die Attribution für OpenStreetMap und CARTO erfolgt automatisch im UI der Karte (siehe `web/templates/index.html`).

## Weitere Informationen

- **NetFlowMap Lizenz**: MIT License (siehe LICENSE-Datei)
- **Projekt-Repository**: https://github.com/kai/netflowmap

---

*Letzte Aktualisierung: 2025-01-27*

