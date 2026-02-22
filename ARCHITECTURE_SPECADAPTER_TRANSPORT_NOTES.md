# SpecAdapter + Transport Architektur (Arbeitsnotiz)

Diese Notiz sammelt die aktuell abgestimmten Design-Entscheidungen rund um
`SpecAdapter`, `Transport` und wiederverwendbare Driver-Bausteine, damit die
Details spaeter strukturiert in die offiziellen Docs uebernommen werden koennen.

## Ausgangspunkt

Bei neuen Paaren wie z. B. `csv-http`, `csv-localfs`, `pdf-http` oder
`rest-localfs` entsteht schnell Copy/Paste:

- gleiche Tool-Signaturen / Function-Descriptions
- gleiche Parsing-Logik fuer Specs
- teilweise gleiche HTTP-Verbindungslogik (Timeout, Proxy, Retry, Headers, ...)

Ziel ist: Wiederverwendung ohne die Driver-Entwicklung unnötig zu verkomplizieren.

## Kernidee: Trennung in drei Rollen

1. **SpecAdapter** (format-/semantikbezogen)
   - konvertiert eine Spezifikation oder fachliche Beschreibung in standardisierte Tools
   - kennt keine Laufzeit-Transportdetails

2. **TransportConnector** (I/O-bezogen)
   - kapselt Verbindungs- und Ausfuehrungslogik (HTTP, LocalFS, S3, ...)
   - kennt keine Tool-Semantik

3. **Driver / ToolDriver** (Komposition)
   - verbindet Adapter + Transport
   - implementiert `list_tools()` / `execute_tool()`
   - optional `MCSDriver`-Funktionen fuer Hybrid-Use-Cases

## Profile vs Adapter

- **Profile** = das fachliche Zielmodell ("was")
  - z. B. `CsvToolProfile` mit kanonischen CSV-Tools
  - kann Presets enthalten (`basic`, `analytics`, ...)

- **Adapter** = die Transformationslogik ("wie")
  - baut ein Profile/Toolset aus Eingabequellen (Datei, Metadaten, Schema, ...)
  - validiert, normalisiert, reduziert, mappt

Empfehlung: Profile und Adapter getrennt halten, aber im gleichen SpecAdapter-Paket.

## Warum diese Richtung robust ist

- Spezifikationslogik wird zentral und testbar
- Transportlogik wird einmal sauber gekapselt und wiederverwendbar
- Driver bleiben duenn: Komposition statt Code-Duplizierung
- Hybrid-Driver bleiben composable (wichtig fuer Orchestrator-Stacking)

## Wichtige Klarstellung

**Spec-Quelle und Execution-Transport sind verschiedene Dimensionen.**

Dass eine Spec auf Platte liegt, bedeutet nicht, dass die Calls lokal ausgefuehrt
werden. Ebenso kann eine Spec per HTTP geladen werden, waehrend Ausfuehrung ueber
einen anderen Connector erfolgt.

## Packaging/Naming (vorlaeufige Richtung)

Fertige Driver behalten das bestehende Muster:

- `mcs-driver-<protocol>-<transport>`

Wiederverwendbare Bausteine als eigene Paketfamilien:

- `mcs-specadapter-<spec>`
  - z. B. `mcs-specadapter-csv`, `mcs-specadapter-openapi`
- `mcs-transport-<transport>`
  - z. B. `mcs-transport-http`, `mcs-transport-localfs`

## Repo-Strategie (aktuelle Praeferenz)

Pragmatischer Start:

- Driver weiterhin in separaten Repos
- SpecAdapter und Transport jeweils als eigenes Mono-Repo (Multi-Package):
  - `mcs-specadapters`
  - `mcs-transports`

So bleibt die Trennung klar, ohne sofort eine Repo-Explosion zu erzeugen.

## Bezug zum Reference-Projekt im `python-sdk`

Um die Architektur ohne externe Abhaengigkeiten sichtbar zu machen, kann die
Reference-Struktur den finalen Zuschnitt bereits illustrieren:

- `mcs-examples/reference/src/mcs/specadapter/...`
- `mcs-examples/reference/src/mcs/transport/...`
- `mcs-examples/reference/src/mcs/driver/...`

Hinweis: Der Name ist konsistent als `specadapter` zu schreiben.

## TCS / Streaming Kontext

Die eingefuehrte `ToolCallSignalingMixin`-Idee bleibt dazu kompatibel:

- Signal/Heuristik liegt beim Driver (oder adapternah)
- Buffer-/Timeout-/UX-Entscheidungen bleiben bewusst im Client
- Dadurch bleibt das Core-Interface schlank und composable

## Offene Punkte fuer spaetere Doku-Uebernahme

- Endgueltige Naming-Empfehlung fuer Profile-Klassen
- Mindest-Interface fuer SpecAdapter/TransportConnector
- Konkretes Beispiel fuer `csv-http` als Multi-Driver-Demo
- Positionierung in den offiziellen Spec-Kapiteln

