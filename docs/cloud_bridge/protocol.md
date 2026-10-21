# Cloud Bridge — contratto backend (protocollo v1)

Questo documento descrive cosa deve implementare il **backend cloud** per
dialogare con il componente `cloud_bridge`. Il lato Home Assistant è
implementato e testato contro un backend di riferimento
(`tests/components/cloud_bridge/fake_backend.py`), che è anche il miglior
esempio eseguibile di questo contratto.

## Principi

- **Nessuna credenziale Home Assistant esce da HA.** Il System User
  `cloud_bridge` non ha username, password né token esportati. Il backend
  conosce solo la **chiave pubblica Ed25519** dell'installazione.
- **Connessione sempre in uscita da HA** (WSS). La porta 8123 non va esposta.
- **Tenant e installazione si derivano dall'autenticazione**, mai dal
  contenuto dei messaggi.
- TLS obbligatorio. `http://` è accettato da HA solo verso loopback (sviluppo).

Codifiche: base64 *URL-safe senza padding* per chiavi, firme e nonce. Le
firme sono Ed25519 su payload testuali con prefisso di dominio, campi
separati da `\n`:

| Uso | Payload firmato |
|---|---|
| Pairing | `cloud_bridge/pair/v1\n<pairing_code>\n<public_key>\n<timestamp>` |
| Autenticazione | `cloud_bridge/auth/v1\n<installation_id>\n<nonce>` |
| Rotazione | `cloud_bridge/rotate/v1\n<installation_id>\n<new_public_key>` |

## 1. Pairing — `POST {cloud_url}/api/bridge/v1/pair`

Prerequisito lato cloud: l'utente, **autenticato nella tua app**, chiede un
codice di pairing. Il backend genera un codice **monouso**, a **scadenza
breve** (es. 10 minuti), formato `[A-Za-z0-9-]{6,64}`, legato a utente e
tenant della sessione. L'utente lo inserisce in Home Assistant (azione
admin `cloud_bridge/pair`).

Richiesta da HA:

```json
{
  "protocol": 1,
  "pairing_code": "PAIR-CODE-0001",
  "public_key": "<base64 32 byte>",
  "timestamp": "2026-10-16T09:00:00+00:00",
  "proof": "<firma Ed25519 del payload di pairing>"
}
```

Il backend deve:

1. consumare il codice in modo atomico (monouso) e rifiutarlo se scaduto;
2. derivare il tenant **dal codice**, non dal body;
3. verificare `proof` con `public_key` (prova di possesso);
4. rifiutare `timestamp` troppo distanti dall'ora corrente (es. ±5 min);
5. creare l'`Installation` con un ID nuovo (`[A-Za-z0-9_-]{1,64}`) e
   registrare la chiave pubblica; audit `paired`.

Risposte: `200 {"installation_id": "ha-001"}`. Errori: `400/401/403/404/409/410`
→ HA mostra `pairing_rejected`; `5xx` → `cloud_error`. HA **non segue
redirect**.

## 2. Connessione — `GET {cloud_url}/api/bridge/v1/ws` (WebSocket)

Frame di testo JSON, max **64 KiB**. HA invia ping ogni 30 s.

```
backend → {"type": "challenge", "nonce": "<≥16 caratteri, casuale, monouso>"}
HA      → {"type": "auth", "protocol": 1, "installation_id": "ha-001",
           "signature": "<firma del payload di autenticazione>"}
backend → {"type": "auth_ok"}
       oppure {"type": "auth_failed", "reason": "<motivo>"}
```

Motivi riconosciuti da HA: `revoked` (HA passa a REVOKED e distrugge la
chiave), `invalid_signature`, `unknown_installation`, `unsupported_protocol`.
Qualunque altro valore viene trattato come `other`. Rispondi a ogni
challenge entro 10 s.

Il backend deve:

- generare un nonce nuovo per **ogni** connessione;
- verificare la firma con la chiave registrata per `installation_id`;
- legare la sessione a `(tenant, installation_id)` e usare **solo quella**
  per autorizzare tutto ciò che segue;
- accettare **una sola sessione attiva** per installazione (chiudere la
  precedente): riduce il danno di una chiave clonata da un backup.

### Dopo `auth_ok`, HA invia

```json
{"type": "snapshot", "revision": 1, "entities": [
  {"entity_id": "light.kitchen", "state": "off",
   "attributes": {"friendly_name": "Kitchen", "brightness": 0},
   "last_changed": "...", "last_updated": "..."}]}
{"type": "state", "revision": 2, "entity_id": "light.kitchen", "state": "on", ...}
{"type": "state_removed", "revision": 3, "entity_id": "light.kitchen"}
```

`revision` cresce in modo monotono **per sessione**; uno snapshot sostituisce
tutto lo stato precedente dell'installazione. Sono inviate solo le entità
scelte dal proprietario e solo una allowlist di attributi.

### Comandi (backend → HA)

```json
{
  "type": "command",
  "command_id": "c9d89491-9a38-4375-bdf9-1a7e9d4a9d18",
  "action": "light.turn_on",
  "entity_id": "light.kitchen",
  "data": {"brightness_pct": 40},
  "expires_at": "2026-10-16T09:00:30+00:00"
}
```

- `command_id`: UUID unico; HA lo memorizza e non esegue mai due volte lo
  stesso ID, anche dopo un riavvio.
- `expires_at`: con fuso orario, nel futuro, al massimo **5 minuti** avanti.
- Campi extra → rifiuto. `installation_id` è facoltativo e, se presente,
  deve coincidere con la sessione.
- Limite: 10 comandi di burst, poi 2/s.

Azioni supportate:

| Azione | `data` |
|---|---|
| `light.turn_on` | `brightness_pct` 0–100, `color_temp_kelvin` 1500–10000 (facoltativi) |
| `light.turn_off`, `light.toggle` | — |
| `switch.turn_on`, `switch.turn_off`, `switch.toggle` | — |
| `fan.turn_on`, `fan.turn_off` | — |
| `fan.set_percentage` | `percentage` 0–100 |
| `cover.open_cover`, `cover.close_cover`, `cover.stop_cover` | — |
| `cover.set_cover_position` | `position` 0–100 |
| `climate.turn_on`, `climate.turn_off` | — |
| `climate.set_temperature` | `temperature` 5–35 |
| `climate.set_hvac_mode` | `hvac_mode` ∈ off, heat, cool, heat_cool, auto, dry, fan_only |

Serrature, allarmi e cover con `device_class` `door`/`garage`/`gate` **non
sono condivisibili né comandabili** in questa versione.

Risposta di HA:

```json
{"type": "command_result", "command_id": "...", "status": "executed",
 "context_id": "01J..."}
```

| `status` | Significato |
|---|---|
| `executed` | la chiamata di servizio è terminata; **non** garantisce lo stato fisico: attendi il messaggio `state` |
| `duplicate` | `command_id` già visto, nulla eseguito |
| `rejected` | `error`: `invalid_command`, `invalid_data`, `expired`, `invalid_expiry`, `installation_mismatch`, `rate_limited`, `entity_not_allowed`, `entity_not_found`, `sensitive_entity`, `action_not_allowed`, `unauthorized` |
| `failed` | `error`: `service_error`, `service_not_found`, `storage_error` |
| `timeout` | nessuna risposta entro 10 s; l'esito arriverà eventualmente tramite `state` |

### Rotazione chiave (avviata dal proprietario in HA)

```
HA      → {"type": "rotate_key", "new_public_key": "...",
           "signature": "<firma con la chiave attuale>",
           "proof": "<firma con la nuova chiave>"}      (stesso payload di rotazione)
backend → {"type": "rotate_key_ok"} | {"type": "rotate_key_failed"}
```

Verifica entrambe le firme, sostituisci la chiave in modo atomico e conserva
la vecchia solo per audit. Se la conferma va persa, HA ritenta
l'autenticazione con la nuova chiave dopo un `invalid_signature`.

### Revoca

- Da HA (proprietario): HA invia `{"type": "revoke"}`, chiude e distrugge la
  chiave. Il backend deve marcare l'installazione `revoked`.
- Dal backend: invia `{"type": "revoke"}` sulla sessione, oppure rispondi
  `auth_failed` con `revoked` alla connessione successiva. HA non si
  ricollega più finché il proprietario non esegue reset e un nuovo pairing.
- Revoca totale (tutte le installazioni di un tenant, o tutte): solo lato
  backend, marcando le installazioni `revoked` e chiudendo le sessioni.

## 3. Schema logico consigliato

`Tenant`, `Membership(user, tenant, ruolo)`, `PairingCode(code_hash, tenant,
user, expires_at, used_at)`, `Installation(id, tenant, state, created_at)`,
`InstallationCredential(installation, public_key, valid_from, revoked_at)`,
`Entity(installation, entity_id, ultimo stato, revision)`,
`EntityPermission(membership, entity, azioni)`, `Command(command_id,
installation, issued_by, action, expires_at, status)`, `Event`, `AuditLog`.

## 4. Controlli obbligatori lato backend (criteri M5)

- Autorizza `utente → tenant → installazione → entità → azione` lato server
  prima di inviare un comando; non fidarti dell'app client.
- Isola per installazione dati, code, topic, connessioni e cache: un
  messaggio ricevuto sulla sessione di HA-001 non può mai aggiornare HA-002.
- Genera `command_id` univoci e `expires_at` brevi; non accodare comandi
  verso un'installazione offline oltre la loro scadenza.
- Non loggare codici di pairing, firme o nonce; registra in audit pairing,
  revoca, rotazione e comandi.
- Verifica TLS con certificati validi; nessun bypass.
