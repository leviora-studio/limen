// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Leviora Studio
/**
 * Demo-Seed für Produkt-Screenshots.
 *
 * ACHTUNG, DESTRUKTIV: löscht ALLE Konten, Clients (außer `dev-client`), Tokens,
 * Passkeys und das Audit-Protokoll, bevor der Demo-Zustand angelegt wird.
 *
 * Legt danach einen vollständig gefüllten Zustand an: Konten der fiktiven „Fachschaft
 * Informatik" (Hochschule Westfeld), registrierte Client-Apps, aktive Verbindungen,
 * Anmeldeverlauf, Audit-Protokoll, 2FA inkl. Recovery-Codes und Passkeys.
 *
 * Alle Daten sind frei erfunden: Domains unter `.example` (RFC 2606), IP-Adressen aus
 * den Dokumentations-Netzen 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (RFC 5737).
 *
 * Damit ein versehentlicher Lauf gegen eine echte Instanz nicht Konten löscht und
 * auch keine Konten mit bekanntem Passwort ins Netz stellt, gelten drei Sperren
 * (siehe `assertSafeTarget`): explizites NODE_ENV=development, eine DATABASE_URL auf
 * localhost, und ein Demo-Passwort, das NICHT im Quelltext steht.
 *
 * Aufruf:
 *   set -a && . ./.env && set +a && NODE_ENV=development npx tsx scripts/seed-demo.ts
 */
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { sql } from 'drizzle-orm';
import sharp from 'sharp';
import {
  auditLog,
  db,
  loginAttempts,
  oauthClients,
  pool,
  refreshTokens,
  totpRecoveryCodes,
  users,
  webauthnCredentials,
} from '../db';
import { encryptSecret, sha256 } from '../lib/crypto';
import { hashPassword, MIN_PASSWORD_LENGTH } from '../lib/password';
import { generateRecoveryCodes, generateTotpSecret, normalizeRecoveryCode, totpUri } from '../lib/totp';

const MIN = 60 * 1000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
const NOW = Date.now();

// ---------------------------------------------------------------------------
// Schutz gegen einen versehentlichen Lauf gegen eine echte Instanz.
// ---------------------------------------------------------------------------

const LOOPBACK = ['localhost', '127.0.0.1', '::1', '[::1]'];

function hostOf(raw: string): string | null {
  try {
    return new URL(raw).hostname;
  } catch {
    return null;
  }
}

/**
 * Bricht ab, wenn die Umgebung nicht nach lokaler Entwicklung aussieht.
 *
 * Drei Sperren, weil dieses Skript Konten LÖSCHT:
 *  1. NODE_ENV muss explizit 'development' sein. Ein ungesetztes NODE_ENV zählt –
 *     wie in lib/env.ts – als Produktion, ist also KEIN Freifahrtschein.
 *  2. DATABASE_URL muss auf einen Loopback-Host zeigen.
 *  3. APP_BASE_URL muss auf einen Loopback-Host zeigen. Nötig, weil Sperre 2 allein
 *     den wichtigsten Restfall NICHT abdeckt: Wer das Skript auf dem Produktions-
 *     server selbst (oder durch einen SSH-Tunnel) ausführt, hat die echte Datenbank
 *     unter localhost. Die öffentliche Issuer-URL verrät diesen Fall.
 *
 * Keine dieser Sperren kennt den Inhalt der Datenbank – das erledigt
 * `assertNoForeignData()` unmittelbar vor dem ersten Löschbefehl.
 */
function assertSafeTarget(): void {
  const problems: string[] = [];

  if (process.env.NODE_ENV !== 'development') {
    problems.push(
      `NODE_ENV ist ${process.env.NODE_ENV ? `'${process.env.NODE_ENV}'` : 'nicht gesetzt'}, ` +
        `erwartet wird 'development'.`,
    );
  }

  const dbUrl = process.env.DATABASE_URL;
  if (!dbUrl) {
    problems.push('DATABASE_URL ist nicht gesetzt.');
  } else {
    const host = hostOf(dbUrl);
    if (host === null) problems.push('DATABASE_URL ist keine gültige URL.');
    else if (!LOOPBACK.includes(host)) {
      problems.push(`DATABASE_URL zeigt auf '${host}', erlaubt sind nur ${LOOPBACK.join(', ')}.`);
    }
  }

  const appUrl = process.env.APP_BASE_URL;
  if (!appUrl) {
    problems.push('APP_BASE_URL ist nicht gesetzt.');
  } else {
    const host = hostOf(appUrl);
    if (host === null) problems.push('APP_BASE_URL ist keine gültige URL.');
    else if (!LOOPBACK.includes(host)) {
      problems.push(
        `APP_BASE_URL ist '${appUrl}' – das sieht nach einer echten Instanz aus, ` +
          `nicht nach lokaler Entwicklung.`,
      );
    }
  }

  if (problems.length === 0) return;

  console.error(
    [
      '',
      '  ✗ Abbruch: Dieses Skript LÖSCHT alle Konten und legt Demo-Daten an.',
      '    Es läuft nur gegen eine lokale Entwicklungs-Datenbank.',
      '',
      ...problems.map((p) => `    · ${p}`),
      '',
      '    Wenn das wirklich eine Wegwerf-Datenbank ist:',
      '      set -a && . ./.env && set +a && NODE_ENV=development npx tsx scripts/seed-demo.ts',
      '',
    ].join('\n'),
  );
  process.exit(1);
}

/** Kürzt eine Fundliste für die Ausgabe auf höchstens fünf Einträge. */
function summarize(items: string[]): string {
  const shown = items.slice(0, 5).join(', ');
  return items.length > 5 ? `${shown} … und ${items.length - 5} weitere` : shown;
}

/**
 * Letzte und wichtigste Sperre, direkt vor dem ersten Löschbefehl: Bricht ab, sobald die
 * Datenbank auch nur einen Datensatz enthält, der nicht zu diesem Demo-Stand gehört.
 *
 * Der Unterschied zu `assertSafeTarget()` ist entscheidend. Jene Sperren prüfen, wo die
 * Datenbank steht – das lässt sich unabsichtlich aushebeln (Skript auf dem Server,
 * SSH-Tunnel, kopierte .env). Diese hier prüft, WAS darin steht, und eine echte Instanz
 * verrät sich immer durch ihre echten Daten.
 *
 * Geprüft werden beide Tabellen, die dieses Skript löscht und die nicht wiederherstellbar
 * sind: `users` und `oauth_clients`. Bei Clients wiegt der Verlust sogar schwerer als bei
 * Konten – mit der Registrierung ist auch der Hash des `client_secret` weg, und da das
 * Secret nur einmal bei der Anlage angezeigt wird, muss jede angebundene App neu
 * eingerichtet werden. Die übrigen gelöschten Tabellen (Tokens, Login-Versuche,
 * Audit-Log) hängen an diesen beiden bzw. sind kurzlebig.
 *
 * Erlaubt bleiben: eine leere Datenbank, ein bereits geseedeter Demo-Stand (erneutes
 * Seeden), das per ADMIN_USER gebootstrappte Erst-Admin-Konto und der von
 * lib/bootstrap.ts außerhalb der Produktion angelegte `dev-client`.
 */
async function assertNoForeignData(): Promise<void> {
  const knownUsers = new Set(PEOPLE.map((p) => p.username.toLowerCase()));
  const bootstrapAdmin = process.env.ADMIN_USER?.trim().toLowerCase();
  if (bootstrapAdmin) knownUsers.add(bootstrapAdmin);

  const knownClients = new Set([...CLIENTS.map((c) => c.clientId), 'dev-client']);

  const [existingUsers, existingClients] = await Promise.all([
    db.select({ username: users.username }).from(users),
    db.select({ clientId: oauthClients.clientId, name: oauthClients.name }).from(oauthClients),
  ]);

  const foreignUsers = existingUsers
    .filter((u) => !knownUsers.has(u.username.toLowerCase()))
    .map((u) => `@${u.username}`);
  const foreignClients = existingClients
    .filter((c) => !knownClients.has(c.clientId))
    .map((c) => `${c.name} (${c.clientId})`);

  if (foreignUsers.length === 0 && foreignClients.length === 0) return;

  const lines = ['', '  ✗ Abbruch: Diese Datenbank enthält fremde Daten.', ''];
  if (foreignUsers.length > 0) {
    lines.push(
      `    ${foreignUsers.length} von ${existingUsers.length} Konten gehören nicht zum Demo-Datensatz:`,
      `      ${summarize(foreignUsers)}`,
      '',
    );
  }
  if (foreignClients.length > 0) {
    lines.push(
      `    ${foreignClients.length} von ${existingClients.length} Anwendungen gehören nicht zum Demo-Datensatz:`,
      `      ${summarize(foreignClients)}`,
      '',
    );
  }
  lines.push(
    '    Das Skript würde sie unwiederbringlich löschen – bei Anwendungen auch deren',
    '    client_secret, was jede angebundene App aussperrt.',
    '    Falls das wirklich eine Wegwerf-Datenbank ist: Daten vorher manuell entfernen.',
    '',
  );

  console.error(lines.join('\n'));
  process.exit(1);
}

/**
 * Demo-Passwort für alle Konten. Bewusst NICHT im Quelltext hinterlegt: sonst stünde
 * in einem öffentlichen Repo ein gültiges Login für jedes geseedete Konto. Aus `.env`
 * (gitignored) über DEMO_PASSWORD, sonst wird ein Zufallspasswort erzeugt und am Ende
 * einmalig ausgegeben.
 */
function demoPassword(): { password: string; generated: boolean } {
  const fromEnv = process.env.DEMO_PASSWORD?.trim();
  if (fromEnv) {
    if (fromEnv.length < MIN_PASSWORD_LENGTH) {
      console.error(
        `\n  ✗ DEMO_PASSWORD ist zu kurz (mind. ${MIN_PASSWORD_LENGTH} Zeichen).\n`,
      );
      process.exit(1);
    }
    return { password: fromEnv, generated: false };
  }
  return { password: `demo-${randomBytes(9).toString('base64url')}`, generated: true };
}

/** Zeitpunkt vor n Tagen (optional mit Uhrzeit-Versatz in Stunden). */
function daysAgo(d: number, hoursOffset = 0): Date {
  return new Date(NOW - d * DAY + hoursOffset * HOUR);
}

/** Deterministischer Hash für reproduzierbare Avatar-Farben. */
function hueOf(seed: string, salt = 0): number {
  let h = salt;
  for (const c of seed) h = (c.codePointAt(0) ?? 0) + (h << 5) - h;
  return Math.abs(h) % 360;
}

// ---------------------------------------------------------------------------
// Avatare: generierte, abstrakte Grafiken (keine Personenfotos).
// ---------------------------------------------------------------------------

/**
 * Erzeugt ein abstraktes 256px-WebP-Profilbild: Farbverlauf plus weiche
 * geometrische Formen, deterministisch aus dem Namen abgeleitet.
 */
async function writeAvatar(dir: string, userId: string, seed: string): Promise<string> {
  const h1 = hueOf(seed);
  const h2 = (h1 + 40 + (hueOf(seed, 7) % 60)) % 360;
  const variant = hueOf(seed, 3) % 4;
  const c1 = `hsl(${h1} 62% 52%)`;
  const c2 = `hsl(${h2} 58% 38%)`;
  const light = `hsl(${h1} 70% 78%)`;

  const shapes = [
    // Variante 0: große versetzte Kreise
    `<circle cx="72" cy="184" r="96" fill="${light}" opacity="0.30"/>
     <circle cx="196" cy="72" r="66" fill="#ffffff" opacity="0.22"/>`,
    // Variante 1: diagonale Bänder
    `<path d="M-40 200 L200 -40 L268 28 L28 268 Z" fill="#ffffff" opacity="0.16"/>
     <path d="M-40 268 L268 -40 L268 22 L22 268 Z" fill="${light}" opacity="0.26"/>`,
    // Variante 2: Bogen / Ring
    `<circle cx="128" cy="128" r="82" fill="none" stroke="#ffffff" stroke-width="26" opacity="0.20"/>
     <circle cx="196" cy="196" r="60" fill="${light}" opacity="0.32"/>`,
    // Variante 3: weiche Blob-Form
    `<path d="M40 150 C40 70 100 30 160 44 C224 58 236 132 210 180 C184 228 96 240 62 206 C36 180 40 168 40 150 Z" fill="#ffffff" opacity="0.18"/>
     <circle cx="88" cy="96" r="44" fill="${light}" opacity="0.30"/>`,
  ][variant];

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="256" height="256" viewBox="0 0 256 256">
  <defs>
    <linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="${c1}"/>
      <stop offset="100%" stop-color="${c2}"/>
    </linearGradient>
  </defs>
  <rect width="256" height="256" fill="url(#g)"/>
  ${shapes}
</svg>`;

  const filename = `${userId}.webp`;
  await sharp(Buffer.from(svg)).webp({ quality: 88 }).toFile(path.join(dir, filename));
  return filename;
}

// ---------------------------------------------------------------------------
// Stammdaten
// ---------------------------------------------------------------------------

const DOMAIN = 'fs-inf.example';

type Person = {
  username: string;
  name: string;
  email: string | null;
  admin?: boolean;
  totp?: boolean;
  inactive?: boolean;
  createdDaysAgo: number;
  lastLoginDaysAgo?: number | null;
};

/** Frei erfundene Personen – keine realen Konten. */
const PEOPLE: Person[] = [
  { username: 'm.haltenbach', name: 'Mira Haltenbach', email: `m.haltenbach@${DOMAIN}`, admin: true, totp: true, createdDaysAgo: 612, lastLoginDaysAgo: 0 },
  { username: 'j.weidenfeld', name: 'Jonas Weidenfeld', email: `j.weidenfeld@${DOMAIN}`, admin: true, totp: true, createdDaysAgo: 468, lastLoginDaysAgo: 1 },
  { username: 'l.brunnthaler', name: 'Lea Brunnthaler', email: `l.brunnthaler@${DOMAIN}`, totp: true, createdDaysAgo: 401, lastLoginDaysAgo: 0 },
  { username: 'a.oezdemir', name: 'Aylin Özdemir', email: `a.oezdemir@${DOMAIN}`, totp: true, createdDaysAgo: 366, lastLoginDaysAgo: 2 },
  { username: 't.kernsen', name: 'Tobias Kernsen', email: `t.kernsen@${DOMAIN}`, createdDaysAgo: 340, lastLoginDaysAgo: 5 },
  { username: 'c.ebersbach', name: 'Charlotte Ebersbach', email: `c.ebersbach@${DOMAIN}`, totp: true, createdDaysAgo: 298, lastLoginDaysAgo: 1 },
  { username: 'f.rothmoser', name: 'Fabian Rothmoser', email: `f.rothmoser@${DOMAIN}`, createdDaysAgo: 264, lastLoginDaysAgo: 9 },
  { username: 'n.sandkuehler', name: 'Nele Sandkühler', email: null, createdDaysAgo: 233, lastLoginDaysAgo: 3 },
  { username: 'p.ronneburg', name: 'Pia Ronneburg', email: `p.ronneburg@${DOMAIN}`, totp: true, createdDaysAgo: 197, lastLoginDaysAgo: 0 },
  { username: 'm.zielinski', name: 'Marek Zieliński', email: `m.zielinski@${DOMAIN}`, createdDaysAgo: 154, lastLoginDaysAgo: 6 },
  { username: 'h.lindqvist', name: 'Hanna Lindqvist', email: `h.lindqvist@${DOMAIN}`, createdDaysAgo: 121, lastLoginDaysAgo: 2 },
  { username: 'd.oberkirch', name: 'David Oberkirch', email: null, createdDaysAgo: 88, lastLoginDaysAgo: 14 },
  { username: 'y.kaplan', name: 'Yusuf Kaplan', email: `y.kaplan@${DOMAIN}`, createdDaysAgo: 76, lastLoginDaysAgo: 4 },
  { username: 's.freytag', name: 'Samuel Freytag', email: `s.freytag@${DOMAIN}`, inactive: true, createdDaysAgo: 553, lastLoginDaysAgo: 41 },
  { username: 'r.altmeier', name: 'Ronja Altmeier', email: `r.altmeier@${DOMAIN}`, inactive: true, createdDaysAgo: 505, lastLoginDaysAgo: 96 },
  { username: 'k.stobbe', name: 'Kilian Stobbe', email: `k.stobbe@${DOMAIN}`, createdDaysAgo: 21, lastLoginDaysAgo: 1 },
];

type ClientDef = {
  clientId: string;
  name: string;
  host: string;
  confidential: boolean;
  firstParty: boolean;
  scopes: string[];
  createdDaysAgo: number;
  /** Auth.js-Callback (Standard) oder abweichender Pfad. */
  callback?: string;
};

const CLIENTS: ClientDef[] = [
  {
    clientId: 'fsinf-protokolle',
    name: 'Protokoll-Tool',
    host: `protokolle.${DOMAIN}`,
    confidential: true,
    firstParty: true,
    scopes: ['openid', 'profile', 'email'],
    createdDaysAgo: 590,
  },
  {
    clientId: 'fsinf-raumbuchung',
    name: 'Raumbuchung',
    host: `raum.${DOMAIN}`,
    confidential: true,
    firstParty: true,
    scopes: ['openid', 'profile'],
    createdDaysAgo: 512,
  },
  {
    clientId: 'fsinf-wiki',
    name: 'Fachschafts-Wiki',
    host: `wiki.${DOMAIN}`,
    confidential: true,
    firstParty: true,
    scopes: ['openid', 'profile', 'email'],
    createdDaysAgo: 447,
    callback: '/oauth2/callback',
  },
  {
    clientId: 'fsinf-wahl',
    name: 'Wahl-Tool (Gremienwahlen)',
    host: `wahl.${DOMAIN}`,
    confidential: true,
    firstParty: true,
    scopes: ['openid', 'profile'],
    createdDaysAgo: 288,
  },
  {
    clientId: 'fsinf-inventar',
    name: 'Inventar & Ausleihe',
    host: `inventar.${DOMAIN}`,
    confidential: false, // Public Client (nur PKCE)
    firstParty: true,
    scopes: ['openid', 'profile'],
    createdDaysAgo: 167,
    callback: '/auth/callback',
  },
  {
    clientId: 'fsinf-cloud',
    name: 'Fachschafts-Cloud',
    host: `cloud.${DOMAIN}`,
    confidential: true,
    firstParty: false, // Drittanbieter → Consent-Screen
    scopes: ['openid', 'profile', 'email'],
    createdDaysAgo: 94,
    callback: '/apps/user_oidc/code',
  },
];

/** IPs ausschließlich aus den RFC-5737-Dokumentationsnetzen + privaten Netzen. */
const CAMPUS_IPS = ['192.0.2.24', '192.0.2.25', '192.0.2.61', '198.51.100.14'];
const HOME_IPS = ['203.0.113.7', '203.0.113.42', '198.51.100.203', '203.0.113.88'];

function pick<T>(list: T[], i: number): T {
  return list[i % list.length];
}

// ---------------------------------------------------------------------------
// Seed
// ---------------------------------------------------------------------------

async function main() {
  assertSafeTarget();
  const { password: DEMO_PASSWORD, generated: passwordGenerated } = demoPassword();

  const uploadDir = process.env.UPLOAD_DIR || './uploads';
  await fs.mkdir(uploadDir, { recursive: true });

  await assertNoForeignData();

  console.log('· Bestehende Demo-Daten entfernen…');
  await db.delete(auditLog);
  await db.delete(loginAttempts);
  await db.delete(refreshTokens);
  await db.delete(webauthnCredentials);
  await db.delete(totpRecoveryCodes);
  await db.delete(users);
  await db.delete(oauthClients).where(sql`${oauthClients.clientId} <> 'dev-client'`);

  // Alle Demo-Konten teilen dasselbe Passwort – ein einziger argon2-Hash spart Zeit.
  console.log('· Passwort-Hash erzeugen (argon2id)…');
  const sharedHash = await hashPassword(DEMO_PASSWORD);

  console.log('· Konten anlegen…');
  const ids = new Map<string, string>();
  let adminTotpSecret: string | null = null;
  let adminRecoveryCodes: string[] = [];

  for (const p of PEOPLE) {
    const id = randomUUID();
    ids.set(p.username, id);
    const created = daysAgo(p.createdDaysAgo, 9);
    const avatarPath = await writeAvatar(uploadDir, id, p.name);

    let totpSecretEnc: string | null = null;
    if (p.totp) {
      const secret = generateTotpSecret();
      totpSecretEnc = encryptSecret(secret);
      if (p.username === 'm.haltenbach') adminTotpSecret = secret;
    }

    await db.insert(users).values({
      id,
      username: p.username,
      name: p.name,
      email: p.email,
      passwordHash: sharedHash,
      // Weit in der Vergangenheit: invalidiert keine frisch erzeugte Session.
      passwordChangedAt: created,
      avatarPath,
      totpSecretEnc,
      totpEnabled: !!p.totp,
      isActive: !p.inactive,
      isSsoAdmin: !!p.admin,
      createdAt: created,
      updatedAt: created,
      lastLoginAt:
        p.lastLoginDaysAgo == null ? null : daysAgo(p.lastLoginDaysAgo, -3),
    });

    // Recovery-Codes für alle 2FA-Konten (einige bereits verbraucht).
    if (p.totp) {
      const codes = generateRecoveryCodes(8);
      if (p.username === 'm.haltenbach') adminRecoveryCodes = codes;
      const usedCount = p.username === 'm.haltenbach' ? 2 : p.username === 'l.brunnthaler' ? 1 : 0;
      await db.insert(totpRecoveryCodes).values(
        codes.map((code, i) => ({
          userId: id,
          codeHash: sha256(normalizeRecoveryCode(code)),
          usedAt: i < usedCount ? daysAgo(30 - i * 11, 4) : null,
          createdAt: created,
        })),
      );
    }
  }

  // Passkeys – reine Anzeige-Datensätze für Screenshots (keine echten Authenticator-
  // Schlüssel; Anmeldung erfolgt über Passwort + TOTP).
  console.log('· Passkeys eintragen…');
  const passkeySeed: Array<[string, string, string[], number, number | null]> = [
    ['m.haltenbach', 'MacBook Pro (Touch ID)', ['internal', 'hybrid'], 344, 0],
    ['m.haltenbach', 'YubiKey 5C NFC', ['usb', 'nfc'], 122, 6],
    ['j.weidenfeld', 'iPhone (Face ID)', ['internal', 'hybrid'], 210, 1],
    ['c.ebersbach', 'Windows Hello (Laptop)', ['internal'], 96, 3],
  ];
  for (const [username, name, transports, createdD, lastUsedD] of passkeySeed) {
    const userId = ids.get(username);
    if (!userId) continue;
    await db.insert(webauthnCredentials).values({
      userId,
      credentialId: randomBytes(32).toString('base64url'),
      publicKey: randomBytes(77).toString('base64url'),
      counter: 12 + (createdD % 40),
      transports,
      name,
      createdAt: daysAgo(createdD, 11),
      lastUsedAt: lastUsedD == null ? null : daysAgo(lastUsedD, -2),
    });
  }

  console.log('· Client-Apps registrieren…');
  for (const c of CLIENTS) {
    const base = `https://${c.host}`;
    await db.insert(oauthClients).values({
      clientId: c.clientId,
      // Secret existiert, ist aber (wie im Produktbetrieb) nur als Hash gespeichert.
      clientSecretHash: c.confidential ? await hashPassword(randomBytes(24).toString('base64url')) : null,
      name: c.name,
      redirectUris: [`${base}${c.callback ?? '/api/auth/callback/limen'}`],
      postLogoutRedirectUris: [`${base}/`],
      allowedScopes: c.scopes,
      isConfidential: c.confidential,
      isFirstParty: c.firstParty,
      createdAt: daysAgo(c.createdDaysAgo, 10),
    });
  }

  console.log('· Aktive App-Verbindungen (Refresh-Tokens) anlegen…');
  // „Verbundene Anwendungen" auf /konto = gültige, nicht widerrufene Refresh-Tokens.
  const connections: Array<[string, string, number]> = [
    ['m.haltenbach', 'fsinf-protokolle', 0],
    ['m.haltenbach', 'fsinf-wiki', 1],
    ['m.haltenbach', 'fsinf-raumbuchung', 3],
    ['m.haltenbach', 'fsinf-cloud', 8],
    ['j.weidenfeld', 'fsinf-protokolle', 1],
    ['j.weidenfeld', 'fsinf-wahl', 2],
    ['l.brunnthaler', 'fsinf-wiki', 0],
    ['l.brunnthaler', 'fsinf-inventar', 5],
    ['c.ebersbach', 'fsinf-protokolle', 2],
    ['a.oezdemir', 'fsinf-raumbuchung', 4],
    ['t.kernsen', 'fsinf-inventar', 6],
    ['p.ronneburg', 'fsinf-cloud', 1],
  ];
  for (const [username, clientId, ageDays] of connections) {
    const userId = ids.get(username);
    if (!userId) continue;
    const client = CLIENTS.find((c) => c.clientId === clientId)!;
    const issued = daysAgo(ageDays, -4);
    await db.insert(refreshTokens).values({
      // Nur der Hash wird gespeichert – das Klartext-Token existiert hier nie.
      tokenHash: createHash('sha256').update(randomBytes(32)).digest('hex'),
      clientId,
      userId,
      scope: client.scopes.join(' '),
      authTime: issued,
      expiresAt: new Date(issued.getTime() + 30 * DAY),
      createdAt: issued,
    });
  }

  console.log('· Anmeldeverlauf schreiben…');
  // Innerhalb von 30 Tagen bleiben, sonst räumt der Wartungsjob sie weg.
  const history: Array<[string, number, number, boolean, string]> = [
    // username, tage, stunden-offset, erfolg, ip
    ['m.haltenbach', 0, -2, true, CAMPUS_IPS[0]],
    ['m.haltenbach', 0, -7, true, CAMPUS_IPS[0]],
    ['m.haltenbach', 1, -3, true, HOME_IPS[0]],
    ['m.haltenbach', 2, -5, false, HOME_IPS[0]],
    ['m.haltenbach', 2, -5.1, true, HOME_IPS[0]],
    ['m.haltenbach', 4, -6, true, CAMPUS_IPS[1]],
    ['m.haltenbach', 6, -9, true, CAMPUS_IPS[0]],
    ['m.haltenbach', 9, -4, false, '203.0.113.201'],
    ['m.haltenbach', 9, -4.05, false, '203.0.113.201'],
    ['m.haltenbach', 11, -8, true, HOME_IPS[1]],
    ['m.haltenbach', 15, -6, true, CAMPUS_IPS[2]],
    ['m.haltenbach', 21, -7, true, CAMPUS_IPS[0]],
  ];
  for (const [username, d, h, success, ip] of history) {
    await db.insert(loginAttempts).values({
      identifier: username.toLowerCase(),
      ip,
      success,
      attemptedAt: daysAgo(d, h),
    });
  }
  // Etwas Grundrauschen für die übrigen Konten (füttert auch die Drossel-Statistik).
  let n = 0;
  for (const p of PEOPLE) {
    if (p.username === 'm.haltenbach' || p.inactive) continue;
    for (const d of [0.5, 2, 5, 9, 17]) {
      await db.insert(loginAttempts).values({
        identifier: p.username.toLowerCase(),
        ip: n % 3 === 0 ? pick(HOME_IPS, n) : pick(CAMPUS_IPS, n),
        success: true,
        attemptedAt: daysAgo(d, -(n % 9)),
      });
      n++;
    }
  }

  console.log('· Audit-Protokoll füllen…');
  const mira = { id: ids.get('m.haltenbach')!, username: 'm.haltenbach' };
  const jonas = { id: ids.get('j.weidenfeld')!, username: 'j.weidenfeld' };
  type Ev = {
    actor: { id: string; username: string };
    action: string;
    target?: string;
    targetUser?: string;
    detail?: string;
    d: number;
    h?: number;
    ip: string;
  };
  const events: Ev[] = [
    { actor: mira, action: 'user.create', target: 'Kilian Stobbe (k.stobbe)', targetUser: 'k.stobbe', d: 21, h: 3, ip: CAMPUS_IPS[0] },
    { actor: mira, action: 'user.reset_password', target: 'Kilian Stobbe (k.stobbe)', targetUser: 'k.stobbe', detail: 'Erstpasswort ausgegeben', d: 21, h: 3.1, ip: CAMPUS_IPS[0] },
    { actor: jonas, action: 'client.rotate_secret', target: 'Fachschafts-Cloud', detail: 'client_id=fsinf-cloud', d: 19, h: 5, ip: CAMPUS_IPS[1] },
    { actor: mira, action: 'user.deactivate', target: 'Ronja Altmeier (r.altmeier)', targetUser: 'r.altmeier', detail: 'Amtszeit beendet', d: 27, h: 6, ip: CAMPUS_IPS[0] },
    { actor: mira, action: 'user.deactivate', target: 'Samuel Freytag (s.freytag)', targetUser: 's.freytag', detail: 'Exmatrikuliert', d: 34, h: 4, ip: HOME_IPS[0] },
    { actor: jonas, action: 'user.update', target: 'Nele Sandkühler (n.sandkuehler)', targetUser: 'n.sandkuehler', detail: 'Name korrigiert', d: 40, h: 7, ip: CAMPUS_IPS[2] },
    { actor: mira, action: 'signing_key.rotate', detail: 'Turnusmäßige Rotation (halbjährlich)', d: 46, h: 2, ip: CAMPUS_IPS[0] },
    { actor: mira, action: 'user.grant_admin', target: 'Jonas Weidenfeld (j.weidenfeld)', targetUser: 'j.weidenfeld', d: 58, h: 8, ip: CAMPUS_IPS[0] },
    { actor: jonas, action: 'user.reset_password', target: 'Marek Zieliński (m.zielinski)', targetUser: 'm.zielinski', detail: 'Passwort vergessen, Identität persönlich geprüft', d: 63, h: 5, ip: CAMPUS_IPS[1] },
    { actor: mira, action: 'client.create', target: 'Fachschafts-Cloud', detail: 'client_id=fsinf-cloud · confidential · Drittanbieter', d: 94, h: 10, ip: CAMPUS_IPS[0] },
    { actor: mira, action: 'user.create', target: 'Yusuf Kaplan (y.kaplan)', targetUser: 'y.kaplan', d: 76, h: 9, ip: CAMPUS_IPS[0] },
    { actor: jonas, action: 'user.create', target: 'David Oberkirch (d.oberkirch)', targetUser: 'd.oberkirch', d: 88, h: 6, ip: HOME_IPS[2] },
    { actor: mira, action: 'client.update', target: 'Raumbuchung', detail: 'Redirect-URI ergänzt', d: 102, h: 4, ip: CAMPUS_IPS[0] },
    { actor: mira, action: 'user.create', target: 'Hanna Lindqvist (h.lindqvist)', targetUser: 'h.lindqvist', d: 121, h: 7, ip: CAMPUS_IPS[2] },
    { actor: jonas, action: 'user.update', target: 'Fabian Rothmoser (f.rothmoser)', targetUser: 'f.rothmoser', detail: 'E-Mail-Adresse gesetzt', d: 133, h: 3, ip: CAMPUS_IPS[1] },
    { actor: mira, action: 'user.create', target: 'Marek Zieliński (m.zielinski)', targetUser: 'm.zielinski', d: 154, h: 5, ip: CAMPUS_IPS[0] },
    { actor: mira, action: 'client.create', target: 'Inventar & Ausleihe', detail: 'client_id=fsinf-inventar · public (PKCE)', d: 167, h: 11, ip: CAMPUS_IPS[0] },
    { actor: jonas, action: 'user.create', target: 'Pia Ronneburg (p.ronneburg)', targetUser: 'p.ronneburg', d: 197, h: 8, ip: CAMPUS_IPS[1] },
    { actor: mira, action: 'signing_key.rotate', detail: 'Turnusmäßige Rotation (halbjährlich)', d: 228, h: 2, ip: CAMPUS_IPS[0] },
    { actor: mira, action: 'user.create', target: 'Nele Sandkühler (n.sandkuehler)', targetUser: 'n.sandkuehler', d: 233, h: 6, ip: CAMPUS_IPS[0] },
    { actor: mira, action: 'user.create', target: 'Fabian Rothmoser (f.rothmoser)', targetUser: 'f.rothmoser', d: 264, h: 9, ip: HOME_IPS[0] },
    { actor: mira, action: 'client.create', target: 'Wahl-Tool (Gremienwahlen)', detail: 'client_id=fsinf-wahl · confidential', d: 288, h: 10, ip: CAMPUS_IPS[0] },
    { actor: mira, action: 'user.create', target: 'Charlotte Ebersbach (c.ebersbach)', targetUser: 'c.ebersbach', d: 298, h: 4, ip: CAMPUS_IPS[2] },
    { actor: mira, action: 'user.create', target: 'Tobias Kernsen (t.kernsen)', targetUser: 't.kernsen', d: 340, h: 7, ip: CAMPUS_IPS[0] },
    { actor: mira, action: 'user.create', target: 'Aylin Özdemir (a.oezdemir)', targetUser: 'a.oezdemir', d: 366, h: 5, ip: CAMPUS_IPS[0] },
    { actor: mira, action: 'client.create', target: 'Fachschafts-Wiki', detail: 'client_id=fsinf-wiki · confidential', d: 447, h: 8, ip: CAMPUS_IPS[0] },
    { actor: mira, action: 'user.create', target: 'Lea Brunnthaler (l.brunnthaler)', targetUser: 'l.brunnthaler', d: 401, h: 6, ip: CAMPUS_IPS[0] },
    { actor: mira, action: 'user.create', target: 'Jonas Weidenfeld (j.weidenfeld)', targetUser: 'j.weidenfeld', d: 468, h: 9, ip: CAMPUS_IPS[0] },
    { actor: mira, action: 'client.create', target: 'Raumbuchung', detail: 'client_id=fsinf-raumbuchung · confidential', d: 512, h: 7, ip: CAMPUS_IPS[0] },
    { actor: mira, action: 'client.create', target: 'Protokoll-Tool', detail: 'client_id=fsinf-protokolle · confidential', d: 590, h: 10, ip: CAMPUS_IPS[0] },
  ];
  for (const e of events) {
    await db.insert(auditLog).values({
      actorUserId: e.actor.id,
      actorUsername: e.actor.username,
      action: e.action,
      targetUserId: e.targetUser ? (ids.get(e.targetUser) ?? null) : null,
      targetLabel: e.target ?? null,
      detail: e.detail ?? null,
      ip: e.ip,
      createdAt: daysAgo(e.d, e.h ?? 0),
    });
  }

  // Zusammenfassung
  const [{ c: userCount }] = await db.select({ c: sql<number>`count(*)::int` }).from(users);
  const [{ c: clientCount }] = await db.select({ c: sql<number>`count(*)::int` }).from(oauthClients);

  console.log('\n✔ Demo-Daten angelegt.');
  console.log(`  Konten:      ${userCount}`);
  console.log(`  Anwendungen: ${clientCount}`);
  console.log(`\n  Login für alle Konten:  Passwort  ${DEMO_PASSWORD}`);
  if (passwordGenerated) {
    console.log(`  ↑ zufällig erzeugt und nirgends gespeichert. Für ein stabiles`);
    console.log(`    Passwort über Seed-Läufe hinweg: DEMO_PASSWORD in .env setzen.`);
  }
  console.log(`  Admin-Konto:            m.haltenbach  (Mira Haltenbach)`);
  if (adminTotpSecret) {
    console.log(`\n  TOTP für m.haltenbach (für den Admin-Bereich nötig):`);
    console.log(`    Secret (Base32): ${adminTotpSecret}`);
    console.log(`    otpauth-URI:     ${totpUri(adminTotpSecret, 'm.haltenbach')}`);
    console.log(`    Recovery-Codes:  ${adminRecoveryCodes.slice(2).join('  ')}`);
  }
  console.log('');
}

main()
  .then(async () => {
    await pool.end();
    process.exit(0);
  })
  .catch(async (err) => {
    console.error(err);
    await pool.end();
    process.exit(1);
  });
