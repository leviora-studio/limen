# Limen – Zentraler Identitätsdienst (OpenID Connect)

Eigenständiger, selbst-hostbarer OpenID-Connect-Identity-Provider (IdP) für kleine bis mittlere
Organisationen. Mehrere interne Web-Apps melden sich zentral hier an (Single Sign-On).
Der Dienst ist **die zentrale Stelle für Identität** (Konten, Login, Profil). **Autorisierung**
(Rollen/Rechte) macht jede App selbst auf Basis der gelieferten Identität.

## Kernentscheidungen

| Thema | Entscheidung |
|---|---|
| Protokoll | OIDC über OAuth 2.0 **Authorization Code Flow + PKCE (S256)** |
| Token | ID-Token & Access-Token als **JWT, RS256**; Refresh-Token opak mit **Rotation** |
| Rollen/Gruppen | **Identität zentral, Autorisierung pro App.** Kein `groups`-Claim. Einzige SSO-Rolle: `is_sso_admin`. |
| E-Mail | Optionales Feld, standardmäßig leer |
| Passwort-Reset | **Nur Admin-Reset** (kein Mailversand; später nachrüstbar) |
| Consent-Screen | Wird für **first-party**-Clients übersprungen |
| Self-Service | Passwort ändern, Name ändern, Avatar verwalten. Username ist **immutabel**. |
| Lizenz | **AGPL-3.0-only** — ausdrücklich nur Version 3, **kein** „or later". © Leviora Studio. |

## Lizenz-Konvention (bei neuen Dateien beachten)

Jede Quelldatei trägt in den ersten beiden Zeilen:

```ts
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Leviora Studio
```

In CSS als Block-Kommentar (`/* … */`). **Nicht** `AGPL-3.0-or-later` (die frühere Angabe, bewusst
abgeschafft) und **nicht** das bloße `AGPL-3.0` (im SPDX-Verzeichnis als veraltet markiert, löst
Warnungen in npm und Lizenz-Scannern aus). Beim Kopieren eines Headers aus älteren Quellen oder aus
dem Gedächtnis prüfen — bei ~95 einheitlichen Headern fällt eine einzelne Abweichung nicht auf.

`LICENSE` ist der wörtliche AGPL-Text der FSF und wird **nie** verändert; das „or later" in seinem
Anwendungs-Anhang ist FSF-Vorlagentext, keine Erklärung dieses Projekts. Fremdlizenzen von
Abhängigkeiten (MIT, Apache-2.0, LGPL …) bleiben ebenfalls unangetastet.

## Tech-Stack

- **Next.js 15** (App Router) + **React 19** + **TypeScript**, `output: 'standalone'`
- **PostgreSQL** via `pg` + **Drizzle ORM** (`drizzle-orm/node-postgres`, pg-core) + `drizzle-kit`
- **Tailwind CSS 3.4** (eigene Design-Tokens, siehe unten)
- **iron-session** v8 – eigene IdP-Browser-Session (Cookie `sso_session`)
- **@node-rs/argon2** – Passwort- & Client-Secret-Hashing (argon2id)
- **jose** – RS256-Signatur, JWK-Export, JWKS, Token-Verifikation
- **otpauth** + **qrcode** – 2FA/TOTP (Secret/Verifikation + QR-Code)
- **@simplewebauthn/server** + **/browser** – WebAuthn/Passkeys (2. Faktor)
- **zod** – Eingabe-Validierung; **nanoid** / Node-`crypto` – IDs/Tokens
- **sharp** – Avatar-Verarbeitung (quadratisch, Resize, Re-Encode)

## Architektur

- **OIDC-Endpunkte**: App-Router **Route Handlers** (`app/.../route.ts`), Node-Runtime.
- **Formulare** (Login/Konto/Admin): **Server Actions** mit Origin-/Host-CSRF-Schutz.
- **IdP-Session** (`sso_session`, iron-session): `{ userId, loginAt }`, HttpOnly/Secure/SameSite=Lax.
  Ermöglicht echtes SSO über mehrere Apps. Strikt getrennt von den OAuth-Tokens der Client-Apps.
- **Signaturschlüssel**: RS256-Keypaar persistent in DB (`signing_keys`), privater PEM
  AES-256-GCM-verschlüsselt (`ENCRYPTION_KEY`). `kid` im JWT-Header, öffentlicher Key über JWKS.
  Rotation möglich (alter Key bleibt bis Ablauf in JWKS).
- **issuer** = `APP_BASE_URL` (öffentliche HTTPS-URL); hinter nginx, `AUTH_TRUST_HOST=true`.

## Datenmodell (Drizzle / pg-core)

```
users         (id UUID PK = "sub", username TEXT UNIQUE/immutabel, name, email NULL,
               password_hash, password_changed_at, sessions_valid_from NULL,
               totp_secret_enc NULL, totp_enabled BOOL=false, totp_last_used_step NULL,
               avatar_path NULL, is_active BOOL=true, is_sso_admin BOOL=false,
               created_at, updated_at, last_login_at NULL)
oauth_clients (id, client_id UNIQUE, client_secret_hash NULL, name,
               redirect_uris TEXT[] (exakter Allowlist-Match), post_logout_redirect_uris TEXT[],
               allowed_scopes TEXT[] (leer = alle), is_confidential BOOL, is_first_party BOOL, created_at)
auth_codes    (code_hash PK, client_id, user_id, redirect_uri, code_challenge, scope,
               nonce NULL, auth_time NULL, expires_at (<=60s), consumed BOOL)
refresh_tokens(token_hash PK, client_id, user_id, scope, auth_time NULL, expires_at,
               revoked_at NULL, rotated_from NULL)   -- atomare Rotation + Reuse-Detection
signing_keys  (kid PK, alg='RS256', public_jwk JSONB, private_pem_enc, active BOOL, created_at)
login_attempts(id, identifier (username ODER 2fa:<userId>), ip, success BOOL, attempted_at)  -- IP- + 2FA-Drossel
totp_recovery_codes(id, user_id FK, code_hash, used_at NULL, created_at)  -- einmalige Backup-Codes
webauthn_credentials(id, user_id FK, credential_id UNIQUE, public_key, counter, transports[],
               name, created_at, last_used_at NULL)  -- Passkeys (2. Faktor)
audit_log     (id, actor_user_id NULL, actor_username, action, target_user_id NULL,
               target_label, detail, ip, created_at)  -- ohne FK, bleibt nach Löschung erhalten
```

`instrumentation.ts` startet zusätzlich einen täglichen Aufräum-Job (`lib/maintenance.ts`):
abgelaufene auth_codes/refresh_tokens, login_attempts (>30 Tage; speist den Anmeldeverlauf)
und inaktive Keys (>2 Tage).

Tokens/Secrets werden **nur gehasht** gespeichert: `auth_codes`/`refresh_tokens` als SHA-256
(hohe Entropie), Passwörter & Client-Secrets als argon2id. Migrationen + Seed beim ersten Start.

## OIDC-Endpunkte & Claims

| Endpunkt | Beschreibung |
|---|---|
| `GET /.well-known/openid-configuration` | Discovery (issuer, Endpunkte, `S256`, `RS256`, scopes, claims) |
| `GET /.well-known/jwks.json` | Öffentliche Signaturschlüssel |
| `GET /authorize` | Session-/Login-Check, PKCE-/Param-Validierung, Consent (non-first-party), Redirect mit `code`+`state` |
| `POST /token` | `authorization_code` (PKCE-Verify) + `refresh_token` (Rotation) → `id_token`,`access_token`,`refresh_token` |
| `GET\|POST /userinfo` | Claims per Bearer-`access_token`; Kill-Switch bei `is_active=false` |
| `POST /revoke` | RFC 7009 Token-Revocation (Refresh-Token), Client-Auth |
| `POST /introspect` | RFC 7662 Token-Introspection (Refresh/Access), Client-Auth |
| `GET /logout` | `end_session_endpoint`, RP-initiated logout, Redirect zu erlaubter `post_logout_redirect_uri` |
| `GET /avatar/[userId]` | Avatar-Datei (oder 404 → App nutzt Initialen-Fallback) |

**Scopes:** `openid`, `profile`, optional `email`.
**Claims:** `sub` (UUID, stabil/immutabel), `preferred_username`, `name`, `picture` (nur wenn Avatar
gesetzt), bei Scope `email` + vorhandener Adresse `email`.

**Token-Lebensdauer:** auth_code ≤ 60 s · id/access ≈ 10 min · refresh ≈ 30 Tage (mit Rotation).

## Seiten (deutsche UI)

- `/login` – Username+Passwort (+ TOTP-Schritt bei aktivem TOTP) **oder** passwortloser Passkey-Login; IP-Drossel
- `/authorize` – OIDC-Einstieg + Consent-Screen (nur non-first-party)
- `/konto` – Passwort/Name/E-Mail ändern, Avatar, **2FA/TOTP + Passkeys** verwalten (inkl. Recovery-Codes neu erzeugen), **verbundene Apps** widerrufen, **überall abmelden**, **Anmeldeverlauf** (Username read-only)
- `/admin` – Konten anlegen/auflisten/**durchsuchen (Username/Name)**/bearbeiten (Name/E-Mail)/(de)aktivieren/PW-Reset/SSO-Admin/2FA zurücksetzen/löschen (nur nach Deaktivierung, mit „LÖSCHEN"-Bestätigung) (Guards: letzten Admin / sich selbst schützen)
- `/admin/clients` – Client-Apps registrieren/bearbeiten; `client_secret` **einmalig** anzeigen
- `/admin/keys` – Signaturschlüssel anzeigen/rotieren
- `/admin/audit` – Audit-Protokoll
- `/logout` – Abmeldung + RP-initiated logout
- `/api/health` – Liveness/Readiness (DB-Ping)
- `/dev/test-client` – nur Entwicklung: spielt den OIDC-Flow durch

## Sicherheit

PKCE S256 erzwungen · `state`+`nonce` durchgesetzt · `redirect_uri` exakter Allowlist-Match
(kein Wildcard/Substring) · kurzlebige Tokens + **atomare** Refresh-Rotation/Revocation +
Reuse-Detection · RS256 (alg gepinnt) + JWKS + Key-Rotation · Cookies HttpOnly/Secure/
SameSite=Lax, in Produktion (HTTPS) `__Host-`-Prefix · CSRF-Schutz (Origin-Check) auf allen
Server Actions; `localhost`-Origin nur außerhalb Produktion erlaubt · **(IP+Konto)-gebundene**
Login-Drosselung (20/15 min pro IP+Konto: kein globaler Konto-Lockout, kein NAT-Kollateral) ·
**(Konto+IP)-gebundene 2FA-Drossel** (`2fa:<userId>` + IP in `login_attempts`, 10/15 min – greift
für Login-2FA **und** Admin-Step-up, überlebt einen Re-Login; IP-Bindung verhindert, dass ein
Passwort-Kenner das Opfer kontoweit aussperrt) · **TOTP-Einmalverwendung** (RFC 6238
§5.2): akzeptierter Zeitschritt wird in `users.totp_last_used_step` atomar verbraucht → kein
Replay eines Codes innerhalb des ±1-Fensters (Login-2FA + Step-up teilen den Zähler) · argon2id
(64 MiB/t=3, Passwort-Länge 10–1024) · `timingSafeEqual` · **`/introspect`+`/revoke` nur mit
vertraulicher Client-Auth** (öffentliche Clients abgelehnt) · App-seitiges Rate-Limit auf
`/authorize`,`/userinfo`,`/introspect`,Avatar-Upload (In-Memory, ergänzend zu nginx) ·
**Avatar-Magic-Byte-Allowlist** (nur PNG/JPEG/WebP/GIF, SVG abgelehnt) ·
generische Login-Fehlermeldungen · Secrets nur aus `.env` · Tokens/Passwörter werden nie
geloggt · `auth_time` im id_token = echter Login-Zeitpunkt (über Refresh-Rotation erhalten) ·
Refresh-Rotation **atomar** (Claim+Ausstellung in einer Transaktion → Reuse-Detection ohne
Race) · Scope wird bei Refresh erneut auf die aktuellen `allowed_scopes` geschnitten
(Scope-Entzug wirkt sofort) · `userinfo`/`introspect` lehnen Access-Tokens ab, die vor
Passwortwechsel/„überall abmelden" ausgestellt wurden (kein 10-min-Restfenster).

**Sessions:** IdP-Session 7 Tage, gleitend per `middleware.ts` erneuert. Passwortänderung
(Self) und Admin-Reset setzen `users.password_changed_at` → ältere SSO-Sessions werden
ungültig und alle Refresh-Tokens des Kontos werden widerrufen. **„Überall abmelden"** (Self)
setzt `users.sessions_valid_from` (invalidiert alle anderen SSO-Sessions) + widerruft alle
Refresh-Tokens; die aktuelle Sitzung bleibt aktiv. **Deaktivieren** (Admin), **2FA-Reset**
(Admin) und **Break-Glass** wirken als echter Kill-Switch: `sessions_valid_from` + Refresh-Token-
Widerruf, sodass alte Sessions/Tokens nicht (z.B. nach Reaktivierung) weiterleben. **Faktor-
Verwaltung** (Passkey/TOTP hinzufügen/entfernen, Recovery-Codes neu) erfordert eine **MFA-Sitzung**,
sobald das Konto **bereits einen Faktor hat** (dann Step-up mit dem vorhandenen Faktor). Der **erste**
Faktor lässt sich aus einer Passwort-Sitzung einrichten (Bootstrap); der erfolgreiche Einrichtungs-
Nachweis (gültiger TOTP-Code bzw. user-verifizierte Passkey-Registrierung) **hebt die Sitzung direkt
auf MFA-Niveau** – kein verwirrendes sofortiges erneutes Bestätigen des gerade angelegten Faktors.
Die Eskalation einer Passwort-only-Sitzung über einen selbst angelegten Faktor wird genau dort
verhindert, wo es zählt: Entfernen/Ändern eines **bestehenden** Faktors verlangt eine MFA-Sitzung
(`factorChangeNeedsStepUp` blockt den Einrichtungs-/Verwaltungspfad, sobald schon ein Faktor existiert).

**Login-Modell:** Entweder **Passwort** (→ TOTP-Schritt nur, falls TOTP eingerichtet) **oder**
**passwortloser Passkey-Login** (discoverable WebAuthn-Credential, user-verifiziert → MFA-stark,
**überspringt den TOTP-Schritt**). **2FA-Methoden:** TOTP (Authenticator-App + einmalige
Recovery-Codes) und/oder Passkeys; optional pro Konto. TOTP-Secret AES-256-GCM-verschlüsselt at rest;
WebAuthn-rpID/Origin aus `APP_BASE_URL`. Signaturschlüssel-Rotation in `/admin/keys`.

**Admin-Zugang (Session-MFA-Enforcement):** Der Admin-Bereich verlangt eine mit zweitem Faktor
erstellte Sitzung (`session.mfa`): entweder Passkey-Login oder Passwort+TOTP. Eine Passwort-only-
Sitzung wird zum **Step-up** nach `/konto?mfa_required=1` geleitet (Passkey/TOTP bestätigen, ohne
Logout). Ohne eingerichteten Faktor → `/konto?2fa_required=1`. Admin kann TOTP+Recovery+Passkeys
eines Kontos zurücksetzen.

**HTTP-Header:** `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy`, HSTS (statisch in `next.config`). **Content-Security-Policy** nonce-basiert
pro Request in `middleware.ts` (`script-src 'self' 'nonce-…' 'strict-dynamic'`,
`frame-ancestors 'none'`); im Dev nur `frame-ancestors`, um HMR nicht zu brechen.
`limitInputPixels` bei Avatar-Verarbeitung (Schutz vor Decompression-Bomb).

## Design-System

`tailwind.config.ts` → `theme.extend.colors.brand`:
`50 #eef5ff · 100 #d9e8ff · 500 #2563eb · 600 #1d4ed8 · 700 #1e40af`.
Body: `bg-slate-50 text-slate-900 antialiased`.
`globals.css` `@layer components`: `.btn`, `.btn-sm`, `.btn-primary`, `.btn-secondary`,
`.btn-danger`, `.input`, `.label`, `.card` (siehe `app/globals.css`).
Eigene Komponenten statt nativer Elemente: `Avatar` (Initialen-Fallback, deterministische HSL),
`Select`, `FileInput`, `Modal`, `SubmitButton`. `noValidate` + eigene Fehlermeldungen,
einheitliche Button-Höhe `h-10`.

Avatar-Initialen-Fallback: max. 2 Zeichen (Teile getrennt an `[\s._-]`, sonst erste 2 Zeichen),
runde Form, Farbe deterministisch: `hash = c + (hash<<5) - hash`, `hue = |hash| % 360`,
`hsl(hue 55% 45%)`, Schrift weiß, `fontSize = size*0.4`.

## Konfiguration (.env)

| Variable | Zweck |
|---|---|
| `APP_BASE_URL` | Öffentliche Issuer-URL, z.B. `https://id.example.com` |
| `AUTH_SECRET` | iron-session-Secret (≥ 32 Zeichen) |
| `DATABASE_URL` | PostgreSQL-Verbindung |
| `POSTGRES_PASSWORD` | DB-Passwort (compose) |
| `ADMIN_USER` / `ADMIN_PASSWORD` | Bootstrap des ersten SSO-Admins |
| `UPLOAD_DIR` | Avatar-Verzeichnis (Volume) |
| `ENCRYPTION_KEY` | 64 Hex (32 Byte) für AES-256-GCM (private Keys at rest) |
| `AUTH_TRUST_HOST` | `true` hinter nginx |
| `TRUSTED_PROXY_SECRET` | Optional: Shared-Secret (`X-Proxy-Auth`-Header von nginx) – die App vertraut X-Real-IP/X-Forwarded-For nur bei passendem Header (Anti-IP-Spoofing) |

Zwei Vorlagen im Repo: **`.env.example`** = schlanke Deploy-Vorlage (`cp .env.example .env`,
`CHANGE_ME`-Platzhalter befüllen); **`.env.example.read`** = ausführlich kommentiertes
Nachschlagewerk mit Erläuterung jeder Variable. Die echte `.env` ist gitignored.

## Bootstrap & Deployment

- `instrumentation.ts` (nur `NEXT_RUNTIME==='nodejs'`, idempotent): Migrationen anwenden →
  ersten Admin seeden → aktiven Signaturschlüssel sicherstellen (sonst generieren).
- `Dockerfile` Multi-Stage (standalone, `node server.js`), `docker-compose.yml` (db + app,
  Volumes `pgdata` + Uploads), nginx terminiert TLS und reicht `X-Forwarded-*`/`Host` durch.

**Deployment-Härtung (Checkliste):**
- **App nicht direkt exponieren:** hinter nginx nur `expose: ['3000']` (App über `app:3000` im
  Docker-Netz erreichen). Lokal ist die Veröffentlichung an `127.0.0.1` gebunden. Direkter
  HTTP-Zugriff an nginx vorbei würde `X-Real-IP`-Spoofing (IP-Drossel/Audit) ermöglichen.
- **nginx setzt `X-Real-IP`/`X-Forwarded-*` + `Host`** (Beispiel-Config). Die App leitet IP-Drossel,
  Audit und Anmeldeverlauf aus `X-Real-IP` ab. Empfohlen: zusätzlich `TRUSTED_PROXY_SECRET`
  setzen und in nginx `proxy_set_header X-Proxy-Auth <secret>;` ergänzen – dann akzeptiert die
  App die Client-IP nur über den Proxy-Pfad (kein `X-Real-IP`-Spoofing bei Direktzugriff).
- **`APP_BASE_URL` = öffentliche HTTPS-URL**, **zur Laufzeit** gesetzt (compose/`.env`), nicht
  zur Build-Zeit. Das Image ist dadurch deployment-URL-unabhängig. Issuer/Redirects/WebAuthn-rpID
  lesen sie über `getEnv()`; CSRF der Server Actions hängt am eingebauten Origin↔Host-Abgleich
  (kein `allowedOrigins` aus `APP_BASE_URL`) → setzt voraus, dass **nginx den korrekten `Host`
  durchreicht** (siehe `nginx.conf.example`). `NODE_ENV=production` (deaktiviert `/dev/*`).
- **Starke Secrets** (`AUTH_SECRET`, `ENCRYPTION_KEY`, `ADMIN_PASSWORD`, `POSTGRES_PASSWORD`) –
  nie die `.env.example`-Platzhalter verwenden.
- **Rate-Limiting auf nginx-Ebene** für `/login` und `/token` empfohlen (Brute-Force/DoS-Schutz
  zusätzlich zur App-internen IP-Drossel). Die App drosselt zusätzlich `/authorize`, `/userinfo`,
  `/introspect` und Avatar-Uploads in-memory; für `/login`+`/token` bleibt nginx maßgeblich.
- **DB-Backups** (pgdata-Volume) einplanen.

## Integration (Konsument, z.B. eine Web-App)

Auth.js/NextAuth „generic OIDC provider" gegen die Discovery-URL `${APP_BASE_URL}/.well-known/openid-configuration`.
Gelieferte stabile Claims: `sub` (Linkage-Key), `preferred_username`, `name`, `picture` (optional),
`email` (optional). Die App legt Nutzer just-in-time an und verwaltet eigene Rollen/Gruppen.
Single-Logout via `end_session_endpoint`.

```ts
// auth.ts (Konsument)
providers: [{
  id: "limen", name: "Limen", type: "oidc",
  issuer: process.env.SSO_ISSUER,           // = APP_BASE_URL
  clientId: process.env.SSO_CLIENT_ID,
  clientSecret: process.env.SSO_CLIENT_SECRET,
  authorization: { params: { scope: "openid profile email" } },
}]
```

## Befehle

```
npm run dev          # Entwicklung
npm run build        # Production-Build (standalone)
npm run db:generate  # Drizzle-Migration aus Schema generieren
npm run db:migrate   # Migrationen anwenden (sonst automatisch beim Start)
npm run verify       # E2E-Verifikation des OIDC-Flows (scripts/verify-oidc.ts)
docker compose up    # DB + App lokal

# Betriebs-/Notfall-Skripte (Server-/DB-Zugriff nötig):
ENCRYPTION_KEY_OLD=<alt> ENCRYPTION_KEY=<neu> npm run rotate-encryption-key  # AES-Umschlüssel rotieren
npm run admin:recover -- --user <name> --reset-2fa --make-admin --activate  # Break-Glass-Recovery

# Demo-Beispieldaten für Screenshots (NUR lokal, siehe Warnung unten):
set -a && . ./.env && set +a && NODE_ENV=development npx tsx scripts/seed-demo.ts
```

**Scopes pro Client:** `oauth_clients.allowed_scopes` (leer = alle unterstützten erlaubt). `/authorize`
schneidet den angefragten Scope darauf zu (`openid` immer erlaubt).

**ENCRYPTION_KEY-Rotation:** `rotate-encryption-key` verschlüsselt alle at-rest-Secrets (Signing-Keys,
TOTP) von OLD auf NEW neu; danach `ENCRYPTION_KEY` dauerhaft setzen und neu starten.

**Break-Glass:** `admin:recover` (nur via Server/DB) setzt für ein Konto 2FA/Passkeys zurück, macht
es zum Admin, aktiviert es und/oder setzt das Passwort — Notfallpfad bei komplettem Admin-Lockout.

**Demo-Seed:** `seed-demo.ts` legt einen vollständig gefüllten Beispielstand an (erfundene Konten,
Client-Apps, Audit-Log, 2FA, Anmeldeverlauf) — Grundlage für Produkt-Screenshots. **Destruktiv:**
löscht vorher alle Konten und Client-Registrierungen. Vier Sperren greifen vor jedem Schreibzugriff:
`NODE_ENV=development` explizit gesetzt · `DATABASE_URL` auf Loopback · `APP_BASE_URL` auf Loopback
(fängt den Lauf auf dem Server selbst bzw. per SSH-Tunnel ab) · `assertNoForeignData()` prüft den
Inhalt von `users`+`oauth_clients` und bricht bei jedem fremden Datensatz ab. Das Demo-Passwort steht
bewusst **nicht** im Quelltext, sondern in `DEMO_PASSWORD` (`.env`); ohne die Variable wird ein
Zufallspasswort erzeugt und einmalig ausgegeben. `tsx` lädt die `.env` nicht selbst — daher das
vorangestellte `set -a && . ./.env`.

## Projektstruktur

```
app/                 # Seiten (Server Components) + Route Handlers (OIDC)
  authorize/ token/ userinfo/ logout/ revoke/ introspect/ .well-known/  # OIDC
  login/ konto/ admin/ consent/ dev/test-client/     # UI
  avatar/[userId]/                                   # Avatar-Auslieferung
components/          # Avatar, Select, FileInput, Modal, SubmitButton, Formulare
db/                  # schema.ts, index.ts (Drizzle)
lib/                 # session, auth, crypto, oidc/* (keys, jwt, pkce, clients, codes, tokens)
drizzle/             # generierte Migrationen
scripts/             # verify-oidc.ts, rotate-encryption-key.ts, admin-recover.ts, seed-demo.ts
instrumentation.ts   # Bootstrap (Migrate + Seed + Keys)
```
