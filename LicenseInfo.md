# License Information

This document lists all external components, libraries, frameworks, and data sources used in NetFlowMap, along with their licenses and sources.

## Backend (Go)

### Direct Dependencies

| Component | Version | Source | License | Usage |
|-----------|---------|--------|---------|-------|
| **go-chi/chi** | v5.2.3 | https://github.com/go-chi/chi | MIT License | HTTP router and middleware |
| **gorilla/websocket** | v1.5.3 | https://github.com/gorilla/websocket | BSD 2-Clause License | WebSocket communication for real-time updates |
| **coreos/go-oidc** | v3.17.0 | https://github.com/coreos/go-oidc | Apache License 2.0 | OpenID Connect authentication |
| **golang-jwt/jwt** | v5.3.0 | https://github.com/golang-jwt/jwt | MIT License | JWT token processing for sessions |
| **oschwald/maxminddb-golang** | v1.13.1 | https://github.com/oschwald/maxminddb-golang | Apache License 2.0 | GeoIP database reader (MaxMind DB format) |
| **golang.org/x/crypto** | v0.46.0 | https://golang.org/x/crypto | BSD 3-Clause License | Cryptographic functions (bcrypt for password hashing) |
| **golang.org/x/oauth2** | v0.34.0 | https://golang.org/x/oauth2 | BSD 3-Clause License | OAuth2 client for OIDC |
| **gopkg.in/yaml.v3** | v3.0.1 | https://github.com/go-yaml/yaml | Apache License 2.0 / MIT License | YAML configuration parsing |

### Indirect Dependencies

| Component | Version | Source | License | Usage |
|-----------|---------|--------|---------|-------|
| **go-jose/go-jose** | v4.1.3 | https://github.com/go-jose/go-jose | MIT License | JOSE implementation (indirect via go-oidc) |
| **golang.org/x/sys** | v0.39.0 | https://golang.org/x/sys | BSD 3-Clause License | System calls (indirect via other packages) |

### Programming Language

| Component | Version | Source | License | Usage |
|-----------|---------|--------|---------|-------|
| **Go** | 1.25.3 | https://golang.org/ | BSD 3-Clause License | Programming language |

## Frontend (JavaScript/CSS)

### JavaScript Libraries

| Component | Version | Source | License | Usage |
|-----------|---------|--------|---------|-------|
| **Leaflet** | 1.9.4 | https://leafletjs.com/ | BSD 2-Clause License | Interactive map visualization |

### Map Tiles (External Services)

| Component | Version | Source | License | Usage |
|-----------|---------|--------|---------|-------|
| **CARTO Basemaps** | - | https://carto.com/basemaps/ | OpenStreetMap ODbL + CARTO Basemaps Terms of Service | Map tiles for dark map view |
| **OpenStreetMap** | - | https://www.openstreetmap.org/ | Open Database License (ODbL) | Map data source for CARTO Basemaps |

**Important Note:** 
- CARTO Basemaps is an **external service** (not a library) that is called at runtime via `cartocdn.com`
- Map tiles are **not redistributed as part of the code**, but are loaded at runtime from CARTO servers
- Attribution is automatically displayed in the UI (see `web/static/js/app.js`)
- CARTO Basemaps uses OpenStreetMap data and provides it as a free tile service
- **Terms of Service:** CARTO's specific "Basemaps Terms of Service" should be reviewed directly: https://carto.com/legal
- Since this is an external service called at runtime, it does **not** prevent redistribution of the NetFlowMap code under an open-source license

### Fonts

| Component | Version | Source | License | Usage |
|-----------|---------|--------|---------|-------|
| **JetBrains Mono** | - | https://fonts.google.com/specimen/JetBrains+Mono | SIL Open Font License 1.1 | Monospace font for technical information |
| **Space Grotesk** | - | https://fonts.google.com/specimen/Space+Grotesk | SIL Open Font License 1.1 | Main font for UI elements |

**Note:** Fonts are loaded via Google Fonts CDN.

## Databases & Data Sources

| Component | Version | Source | License | Usage |
|-----------|---------|--------|---------|-------|
| **DB-IP Lite City** | Updated monthly | https://db-ip.com/db/lite.php | Creative Commons Attribution 4.0 International (CC BY 4.0) | GeoIP location database (city, country, coordinates) |
| **DB-IP Lite ASN** | Updated monthly | https://db-ip.com/db/lite.php | Creative Commons Attribution 4.0 International (CC BY 4.0) | ASN database (Autonomous System Number, organization) |

**Note:** Both databases are automatically downloaded by NetFlowMap and updated monthly. The databases are provided in MaxMind DB format.

## Build Tools & Runtime

| Component | Version | Source | License | Usage |
|-----------|---------|--------|---------|-------|
| **Alpine Linux** | 3.19 | https://alpinelinux.org/ | Apache License 2.0 | Base image for Docker container |
| **golang:1.25-alpine** | - | https://hub.docker.com/_/golang | BSD 3-Clause License (Go) | Build container for Docker builds |

## License Compatibility

All licenses used are compatible with NetFlowMap's MIT License:

- **MIT License**: Multiple components (go-chi, golang-jwt/jwt, go-jose)
- **Apache License 2.0**: Multiple components (go-oidc, maxminddb-golang, yaml.v3, Alpine Linux)
- **BSD 2-Clause / BSD 3-Clause**: Go standard libraries and Leaflet
- **SIL Open Font License 1.1**: Fonts (compatible with MIT)
- **Creative Commons Attribution 4.0**: GeoIP databases (CC BY 4.0 requires attribution)
- **Open Database License (ODbL)**: OpenStreetMap data (via CARTO Basemaps)
- **CARTO Basemaps**: External service, no code redistribution required

**Important:** CARTO Basemaps is an external service called at runtime. The terms of service apply to using the service at runtime, not to code distribution.

## Attribution Requirements

### CC BY 4.0 (DB-IP Lite)
The GeoIP databases from DB-IP Lite are licensed under CC BY 4.0 and require attribution. This is implicitly provided through the use of the databases in the project.

### OpenStreetMap (via CARTO Basemaps)
Attribution for OpenStreetMap and CARTO is automatically displayed in the map UI (see `web/templates/index.html`).

## Further Information

- **NetFlowMap License**: MIT License (see LICENSE file)
- **Project Repository**: https://github.com/RiskIdent/NetFlowMap

---

*Last updated: 2025-01-27*
