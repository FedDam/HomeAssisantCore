# Cloud Bridge — architettura e decisioni version-specific

> Stato: **M0–M4 implementati e testati lato Home Assistant; M5 coperto per
> la parte HA.** Non production-ready finché il backend reale non implementa
> `protocol.md` e non viene eseguito un test end-to-end in container.

## 1. Baseline verificata (M0)

| Voce | Valore |
|---|---|
| Upstream | `https://github.com/home-assistant/core.git` (remote `upstream`; nessun `origin` configurato) |
| Tag di partenza | `2026.10.1` (ultimo stabile al 2026-10-16) |
| Commit | `abe1fdd7cd6b4de1715c87b6fd87d92699514ef9` (2026-10-10) |
| Branch di lavoro | `feature/cloud-bridge-m1` |
| `pyproject.toml` | `version = "2026.10.1"`, `requires-python = ">=3.14.2"` |
| Python usato | 3.14.5, venv creato con `uv 0.12.23` |
| Tool | pytest 9.0.3, ruff 0.16.9, mypy, pylint, `python -m script.hassfest` |
| Dipendenze nuove | nessuna (`cryptography`, `aiohttp`, `probatio` sono già dipendenze del Core) |

### API verificate

| API | Firma reale nel tag | Uso |
|---|---|---|
| `async_create_system_user` | `(name, *, group_ids=None, local_only=None)` | identità |
| `async_get_users`, `async_get_user` | `()`, `(user_id)` | verifica per ID |
| `async_update_user` | `(user, name=, is_active=, group_ids=, local_only=)` | rinomina / migrazione gruppo |
| `async_create_refresh_token` | per `system_generated` forza `TOKEN_TYPE_SYSTEM` | **non usata** (vedi §4) |
| `_user_should_be_owner` | owner = primo utente non di sistema | onboarding intatto |
| `Store(...)` | `private`, `atomic_writes` presenti | tutti gli store del bridge |
| `entity_service_call` | utente non admin → `user.permissions.check_entity` | motivo del gruppo utente |

Lo store auth salva con ritardo di 1 s (`DEFAULT_SAVE_DELAY`): gestito dalla
macchina a stati dell'identità (§3).

## 2. Bootstrap e manifest

- `hass.auth` è creato in `async_process_ha_core_config`, **dopo**
  `CORE_INTEGRATIONS`. Il bridge è quindi in **`DEFAULT_INTEGRATIONS`**
  (stage 2): nessun YAML, nessun `custom_components`, non caricato in
  recovery mode (fail closed voluto). `async_setup` ritorna sempre `True`.
- Manifest: `integration_type: system` (con `service` comparirebbe in
  «Aggiungi integrazione» come integrazione YAML), `iot_class: cloud_push`,
  `quality_scale: internal` (+ `NO_QUALITY_SCALE` in hassfest),
  `dependencies: ["websocket_api"]`.
- La connessione parte con `async_at_started` e si chiude su
  `EVENT_HOMEASSISTANT_STOP`.

## 3. Identità (M1) — `system_user.py`

System User `cloud_bridge`: `system_generated`, `local_only=True`, nessuna
credenziale, gruppo **`system-users`** (non admin).

**Perché il gruppo utente** (cambio rispetto all'MVP senza gruppi): in HA i
permessi sono a gruppi fissi. Un utente senza gruppi viene rifiutato
(`Unauthorized`) da ogni servizio su entità; un contesto senza utente
salterebbe *tutti* i controlli e perderebbe l'attribuzione. Con
`system-users` HA autorizza il controllo delle entità ma blocca i servizi
admin-only, i comandi risultano «eseguiti da cloud_bridge» e l'allowlist del
bridge restringe ulteriormente. È lo stesso schema dell'integrazione `voip`.
Le identità create prima del cambio (senza gruppo) vengono migrate dopo la
verifica per ID.

Record `.storage/cloud_bridge.identity`: `phase`, `system_user_id`, `nonce`,
`disabled`. Creazione crash-safe con nonce: un orfano si adotta solo se il
nome contiene il nonce salvato e non ha credenziali/token; mai per nome.
Stati: READY, DISABLED, INACTIVE (mai riattivato), ERROR (repair issue, fail
closed). Dettaglio dei casi nei test `test_system_user.py`.

## 4. Credenziali (M2) — `credentials.py`

- **Modello scelto: nessun token HA esportato.** Il cloud non chiama le API
  di HA; HA esegue i comandi in processo. Nessun refresh token viene creato.
- Ogni installazione genera una coppia **Ed25519** al pairing. Solo la
  chiave pubblica esce. Privata in `.storage/cloud_bridge.credentials`
  (privato, scrittura atomica).
- **Rotazione**: chiave pendente persistita prima dell'invio; commit alla
  conferma; se la conferma si perde, al riavvio HA prova la chiave pendente
  dopo un `invalid_signature` e la promuove se accettata.
- **Revoca per installazione**: stato `REVOKED` persistito *prima* della
  distruzione della chiave (un crash viene completato al boot). Al riavvio
  nessuna connessione, nessuna chiave ricreata.
- **Revoca totale**: lato backend (vedi `protocol.md`).
- **Perdita credenziali**: link ACTIVE senza chiave → bloccato
  (`credentials_missing`); recupero esplicito: revoke → reset → nuovo pairing.

## 5. Pairing multi-tenant (M3) — `provisioning.py`

Macchina a stati persistita in `.storage/cloud_bridge.link`, ogni
transizione in audit (ultimi 200 eventi):

```
UNPROVISIONED → PAIRING → ACTIVE ⇄ SUSPENDED
                   │         │         │
                   └────→ REVOKED ←────┘ ;  REVOKED → UNPROVISIONED (reset esplicito)
```

- Transizioni esplicite; richiedere lo stato corrente è un no-op.
- Pairing avviato da un **admin locale** con un codice monouso emesso dal
  backend a una sessione autenticata; il tenant è derivato dal codice.
  Prova di possesso della chiave. URL backend: HTTPS obbligatorio (HTTP solo
  loopback), niente redirect, niente credenziali nell'URL.
- `PAIRING` trovato al boot → chiave distrutta, ritorno a `UNPROVISIONED`.
- Cambio tenant solo con revoke → reset → nuovo pairing.
- Il pairing richiede identità READY e tutti i record leggibili.

## 6. Connessione e comandi (M4)

- `cloud_client.py`: WSS in uscita, challenge firmata, timeout (connessione
  15 s, handshake 10 s), heartbeat 30 s, max 64 KiB per frame, backoff
  esponenziale 1 s → 300 s con jitter, coda di invio limitata (overflow →
  riconnessione + snapshot), motivi di errore del server mai loggati verbatim.
- `device_sync.py`: snapshot + `state`/`state_removed` con `revision`; solo
  entità scelte dal proprietario (max 500) e allowlist di attributi; entità
  che diventano sensibili vengono ritirate.
- `command_handler.py`: schema rigoroso, azioni fisse (nessun
  `domain/service` libero, niente shell/Python/URL), entità condivisa e dello
  stesso dominio, scadenza ≤ 5 min, `command_id` persistito **prima**
  dell'esecuzione (no doppia esecuzione, anche dopo riavvio), rate limit,
  timeout 10 s, risultato strutturato che distingue *eseguito* da *stato
  osservato*. Serrature, allarmi, porte, cancelli e garage bloccati.
- `websocket_api.py`: comandi **admin-only** `cloud_bridge/status`, `pair`,
  `suspend`, `resume`, `revoke`, `reset`, `rotate_key`,
  `set_exposed_entities`. Nessun endpoint HTTP nuovo.

Contratto per il backend: **`docs/cloud_bridge/protocol.md`**.

## 7. M5 — copertura lato HA

| Criterio bloccante | Lato HA | Test |
|---|---|---|
| Tenant A non controlla entità di B alterando payload | `installation_id` del payload ≠ sessione → rifiuto; entità non condivisa → rifiuto | `test_command_handler`, `test_cloud_link::test_command_round_trip` |
| HA-001 non legge/pubblica dati di HA-002 | firme legate a `installation_id`, chiavi uniche | `test_credentials::test_keys_are_unique_per_installation` (+ backend) |
| Chiave revocata non si riconnette né si ricrea | `REVOKED` persistente, chiave distrutta | `test_local_revoke_survives_restart`, `test_revoked_on_authentication` |
| Stesso `command_id` non esegue due volte | dedup persistente | `test_duplicate_is_not_executed_twice`, `test_replay_after_reconnect_is_not_executed` |
| Comandi scaduti non eseguiti dopo riconnessione | `expires_at` obbligatorio | idem |
| Nessuna credenziale valida su altri HA | Ed25519 per installazione | `test_keys_are_unique_per_installation` |
| Cloud guasto → controllo locale | bridge isolato, setup sempre `True` | `test_cloud_offline_keeps_home_assistant_running` |

La metà backend di questi criteri (autorizzazione server-side, isolamento
per tenant, sessione unica) è responsabilità del backend: vedi
`protocol.md` §4.

## 8. Rischi aperti

1. **Backup = clone della chiave.** La chiave privata è in `.storage` e
   finisce nei backup di HA; ripristinare un backup su un altro dispositivo
   ne clona l'identità. Mitigazioni: sessione unica per installazione lato
   backend, rotazione dopo un ripristino, revoca. HA non offre un vault né
   un'esclusione dal backup per singoli file.
2. **Orologio di HA.** Scadenze verificate con l'ora locale: un orologio
   sbagliato fa rifiutare i comandi (fail closed).
3. **Nessuna UI.** I comandi admin sono solo WebSocket (pannello o card da
   sviluppare).
4. **Permessi HA a grana grossa.** Il gruppo `system-users` controlla tutte
   le entità; la restrizione per entità è dell'allowlist del bridge.
5. **Sensibili disabilitati.** Serrature/allarmi/porte richiedono una policy
   separata (es. conferma locale o PIN) non ancora progettata.
6. Non testato in container, HA OS o Supervisor; `origin` del fork da
   configurare; nessun commit eseguito.
