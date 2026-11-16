# Implementation notes

Technical breakdown of the Vencord E2EE plugin. For installation and everyday use, see [README.md](README.md).

**Protocol v2.**

---

## Contents

- [How it works](#how-it-works)
- [Wire format](#wire-format)
- [Message frames and compression](#message-frames-and-compression)
- [Message length limit](#message-length-limit)
- [Encryption at rest](#encryption-at-rest)
- [Security properties](#security-properties)
- [Upgrading from v1](#upgrading-from-v1)
- [What is not protected](#what-is-not-protected)
- [Repository layout](#repository-layout)
- [Tests](#tests)

## How it works

1. On first run, generates a long-term X25519 identity keypair and stores it locally (Vencord's `DataStore`, backed by IndexedDB).
2. Adds a lock button to the chat bar in DMs. Clicking it enables E2EE for that conversation.
3. The handshake is a 2-message round trip (INIT + ACK) carrying both users' identity pubkeys and one-time ephemeral pubkeys. The shared secret is derived from a 4-DH mix (mutual identity × ephemeral) — a trimmed-down X3DH.
4. Once the handshake completes, every message is run through the Double Ratchet: a fresh DH ratchet step on every conversation "turn", with a symmetric KDF chain producing a per-message AEAD key.
5. Out-of-order delivery is handled by caching skipped message keys (capped at 200 per chain).
6. Decrypted plaintext is cached locally so reloading a channel doesn't re-show ciphertext.

## Wire format

Discord (and anyone else reading the channel) sees:

```
🔐⟨E2EE v2⟩AAECAwQF...long-base64-blob...==
```

The full protocol:

```
Alice → Bob:   🔐⟨E2EE-INIT v2⟩base64(IdA‖EphA)
Bob   → Alice: 🔐⟨E2EE-ACK  v2⟩base64(IdB‖EphB)
… both compute SK = HKDF(DH₁‖DH₂‖DH₃‖DH₄) …

Alice → Bob:   🔐⟨E2EE v2⟩base64(header‖ct)
Bob   → Alice: 🔐⟨E2EE v2⟩base64(header‖ct)

Either side:   🔐⟨E2EE-RESET v2⟩
```

`header` is 40 bytes: 32-byte sender ratchet pubkey + 4-byte previous-chain length + 4-byte message number. `ct` is AES-GCM output (ciphertext + 16-byte auth tag). The header is bound to the AEAD as additional data.

The INIT is stashed as a pending invitation and never auto-answered — the ACK is only built after an explicit user gesture, so a hostile peer can't trigger outbound traffic by spamming invitations. The safety number is computed as soon as the INIT arrives (it only needs the two identity keys), so it can be compared before accepting.

RESET carries no proof of who sent it. Receiving one discards the session but does not turn E2EE off: the channel moves to a `peer-reset` phase in which every send is refused, until the user explicitly chooses to re-handshake or to continue unencrypted.

## Message frames and compression

The bytes fed to the ratchet are a *frame*, not bare UTF-8:

```
[1 byte codec flag][payload]

0x00  raw       payload is UTF-8 plaintext
0x01  deflate   payload is raw-DEFLATE of UTF-8 plaintext
```

The flag lives **inside** the AEAD, so it is authenticated — Discord cannot flip a message between codecs.

`packFrame` compresses speculatively and keeps the result only if it is **strictly smaller** than the raw bytes *and* inflates back to byte-identical input. The round-trip check costs one inflate on an already-small buffer and buys a hard guarantee: a compression-layer bug can never silently ship a message the peer decodes into different text. Any failure in that path — unsupported platform, throwing stream, mismatched round-trip — falls through to the raw frame, which always works.

Messages under 64 bytes skip compression entirely. Raw DEFLATE's block overhead means short text always comes out larger, and most Discord messages are short, so the common case is a raw frame costing one extra byte.

`deflate-raw` is used rather than `deflate` or `gzip`: no zlib header (2 bytes), no gzip header/trailer (18 bytes). At chat message sizes those fixed overheads are a meaningful share of the win.

### Stream handling

`compress.ts` pushes bytes through `ReadableStream → pipeThrough → Response.arrayBuffer()` rather than driving a writer manually. The naive approach — grab a writer, `await write()`, `await close()`, then read — can deadlock, because the transform's output queue fills while nothing drains it. It also strands a floating promise that surfaces as an unhandled rejection when the stream errors. The stream-source shape has exactly one awaited promise, resolves backpressure on its own, and lets `arrayBuffer()` concatenate chunks — removing the hand-rolled offset arithmetic that would otherwise be the likely source of byte corruption on multi-chunk payloads.

### Compression and encryption

Compression happens **inside** the AEAD. The usual caveat about compressing before encrypting (CRIME/BREACH) applies in principle — compressed length leaks something about content. Those attacks need an oracle that lets an attacker inject chosen text into your plaintext and observe the resulting size, repeatedly. A DM composer isn't that, and message length is already visible to Discord regardless.

## Message length limit

Discord caps a message at 2000 characters. With a 40-byte header, a 16-byte auth tag and 33% base64 expansion, the plaintext ceiling is around **1434 characters** for text that doesn't compress — and considerably higher for text that does (repetitive text of 4000+ characters routinely fits).

`projectedWireLength()` computes the finished size exactly rather than estimating: AES-GCM ciphertext is exactly plaintext + tag, and base64 expansion is a pure function of length. The check runs **before `ratchetEncrypt`**, which matters — the ratchet mutates the sending chain on every call, so a message rejected after encryption would burn a message key and leave a permanent gap in the numbering the peer sees. Rejecting first makes a refused send a complete no-op.

Length is measured in UTF-16 code units (`String.length`), which over-counts the prefix by one versus code points because 🔐 is a surrogate pair. Erring high is the safe direction.

Chunking across multiple messages is not implemented.

## Encryption at rest

Optional, off by default. When enabled, the user sets a password and is prompted for it once at startup.

| Store | Encrypted | Rationale |
|---|---|---|
| identity key | yes | the long-term X25519 private key |
| sessions | yes | root keys, chain keys, cached skipped message keys |
| decrypted cache | yes | the plaintext of every message read |
| enabled channels | no | see below |
| processed message IDs | no | reveals nothing the account doesn't |
| pinned peer keys | no | public keys |

`enabled` deliberately stays in the clear. It is the only record of "this DM is supposed to be encrypted", and a locked plugin needs it to know it must **refuse** to send rather than let a message go out unencrypted.

### KDF choice

**PBKDF2-SHA256, 600,000 iterations** (OWASP's 2023 floor), with a 16-byte random salt, wrapping records in AES-256-GCM under a fresh random 96-bit IV per record.

Argon2id would be the better primitive and is deliberately not used, because it isn't reachable here: WebCrypto exposes no Argon2, and a pure-JS Argon2id at a memory cost high enough to matter (64 MiB+) takes many seconds per unlock in a renderer process — slow enough that users would disable the feature, which is worse than a weaker KDF. PBKDF2 runs natively in a few hundred milliseconds.

The tradeoff is memory-hardness: PBKDF2 parallelises well on GPUs, so password length matters much more here than it would with Argon2id. A 12-character minimum is enforced in the UI for that reason.

The algorithm and its parameters are recorded in each stored blob rather than assumed, and `deriveVaultKey` dispatches on the descriptor and rejects unrecognised ones. Adding Argon2id later is therefore a data migration, not a redesign. A stored descriptor below `MIN_PBKDF2_ITERATIONS` is refused, so tampering with the on-disk parameters can't downgrade the KDF.

### Scope

This protects data at rest — a stolen disk image, a backup, another account on a shared machine. It does *not* protect against anything running as you while Discord is open: the derived key stays in memory so incoming messages can be decrypted without prompting on every keystroke.

### Locked state

If the user dismisses the unlock prompt, the plugin runs locked: no identity, no sessions, the lock button turns 🔑, sends in E2EE channels are refused (never silently downgraded to plaintext), and nothing is written to storage. That last point matters — every in-memory map is empty while locked, so an unguarded write would serialise "no identity, no sessions, no cached messages" straight over the user's real encrypted data. The same guard covers every other moment the stores have not been read yet, such as changing the password setting while the plugin is switched off.

E2EE messages that arrive while locked are rendered as a placeholder, which overwrites Discord's copy of the ciphertext. The plugin keeps its own copy of each (up to 500) and feeds them back through the normal incoming path once the vault is unlocked, oldest first. The lock only comes off after every store has been read successfully; if one is unreadable the plugin stays locked rather than running on half-loaded state.

The unlock prompt is **not awaited** during plugin start. Blocking `start()` on a modal would stall Vencord's startup, and the modal needs Discord's UI mounted to render at all. Instead the plugin marks itself locked *before* installing message hooks, then prompts asynchronously; the 🔑 button is the retry path if the prompt never appears.

### Ordering during setup

Vault metadata is published **before** the data is rewritten, so an interruption fails in the recoverable direction. Metadata present alongside still-plaintext stores is self-healing: the next start asks for the password, `readSecret` passes plaintext records through untouched, and the next write encrypts them. The reverse order would leave encrypted blobs with no metadata to derive a key from — permanently unreadable.

### Settings UI

The toggle is an `OptionType.COMPONENT`, not a `BOOLEAN`. Vencord's `BooleanSetting` keeps the switch position in local React state and never re-reads the store, so cancelling the password prompt would revert the stored value while leaving the switch visibly ON. For a security setting that's the worst possible failure — it would tell the user their messages are encrypted when they aren't. The component instead derives the switch from whether vault metadata actually exists, so it cannot lie.

## Security properties

**Forward secrecy.** Past messages cannot be decrypted by an attacker who later compromises your ratchet state, because each DH ratchet step derives a fresh root key and chain key.

**Break-in recovery.** After a ratchet step, an attacker who had your old state loses the ability to decrypt future messages.

**Safety numbers.** The first handshake is trust-on-first-use (TOFU). To defend against a hypothetical MITM (e.g. a malicious Discord), both users should compare their safety number out of band. It is shown in a toast when the session becomes ready and in the lock button's tooltip.

**Key change detection.** Each peer's identity pubkey is pinned per user ID the first time a handshake completes, and survives session resets. A later handshake carrying a *different* identity key — what a MITM forcing a re-handshake looks like, and also what a peer reinstalling the plugin looks like — is held rather than completed. On the responder side the invitation cannot be accepted by typing, only through a dialog that shows the new safety number. On the initiator side the session keys are derived but the session is flagged `untrustedKey`: the new key is not pinned, the priming message is not sent, and sends are refused until the user confirms in the same dialog. The flag is persisted, so the ⚠️ survives a restart.

**Resets fail closed.** See [Wire format](#wire-format): an unauthenticated RESET can end a session but cannot put a DM back into plaintext. Turning a live session off locally also asks for confirmation first.

**One ratchet step at a time.** Everything that touches a channel's session — incoming messages, sends, lock-button actions — runs through one per-channel queue (`serial.ts`). An encrypt overlapping a decrypt is not cosmetic: the decrypt's commit rolls the sending chain back, and the next message is sealed under a message key and IV that were already used. Saves go through a single ordered writer that snapshots the sessions and the plaintext cache together and writes the plaintext first, so a session that has consumed a message key never reaches disk ahead of that message's plaintext.

**Failed decryption never desyncs state.** `ratchetDecrypt` performs all ratchet steps on a working copy and commits only after the AEAD authenticates. Without this, a single corrupted or forged message whose header triggered a bogus DH ratchet would permanently break a live session.

**Handshake replay protection.** Handshake message IDs are recorded persistently. History loads (`LOAD_MESSAGES_SUCCESS`) re-feed old messages through the incoming path, and without de-duplication a stale INIT would be reprocessed as fresh — deriving a new shared secret, overwriting the live session, and firing a stray ACK into the channel.

**Edit blocking.** Discord edits bypass the encryption hook, so editing an encrypted message would send the new text in plaintext. Edits are blocked in E2EE channels.

**Fail-closed sends.** Once a DM is E2EE-enabled, every path out of the send hook either encrypts or cancels. There is no branch that hands the message back to Discord unencrypted — including errors: Vencord logs a send listener that throws and then sends the message as typed, so the hook catches everything and cancels.

**Failed sends are restored.** The optimistic local echo is rewritten to plaintext for display; on `MESSAGE_SEND_FAILED` the ciphertext is put back, so Discord's retry affordance can't ship the plaintext. Failed IDs are remembered, so an echo that is only processed after its failure was announced is left untouched.

## Upgrading from v1

v1 and v2 are deliberately **not interoperable**. The wire markers, the AEAD additional-data string and the handshake HKDF info string all changed, so the two versions cannot derive matching keys. A v1 message renders as a labelled placeholder rather than being mis-decrypted.

On first run after upgrading, the plugin migrates automatically:

- **Identity key and pinned peer keys carry over.** They're plain X25519 material with no protocol version in them. Regenerating them would make every peer's client shout "identity key CHANGED" — training users to click through the exact warning that is supposed to mean *possible MITM*.
- **Cached plaintext and enabled channels carry over.**
- **Sessions are dropped.** v1 ratchet state is only valid under v1's AEAD binding, and the peer will upgrade at a different time anyway. Enabled DMs simply re-handshake on the next message.
- **Processed handshake IDs are not carried over.** v1 handshake messages no longer reach any state-mutating branch, so the de-dupe set has nothing left to protect.
- **v1 records are deleted**, not kept as a backup — they contain the identity private key in the clear, and leaving a plaintext copy would quietly defeat at-rest encryption.

## What is not protected

- **Metadata.** Discord still sees who talks to whom, when, message sizes, channel IDs, and the fact that E2EE is in use (the marker is plaintext).
- **Attachments, embeds, replies, reactions.** Text only.
- **Group DMs and guild channels.** 1:1 DMs (channel type 1) only.
- **The local plaintext cache**, unless at-rest encryption is enabled.

## Repository layout

| File | Purpose |
|---|---|
| `crypto.ts` | X25519/HKDF/AES-GCM primitives and Double Ratchet state machine |
| `compress.ts` | DEFLATE wrappers used for message frames |
| `session.ts` | Session lifecycle, handshake, wire format, framing, size accounting |
| `vault.ts` | Password KDF and AES-GCM wrapping for encryption at rest |
| `serial.ts` | Per-channel queue and ordered writer that keep ratchet steps and saves from overlapping |
| `PassphraseModal.tsx` | Password prompt UI |
| `ChoiceModal.tsx` | Confirmation dialogs (turn off, peer reset, changed key) |
| `index.tsx` | Vencord plugin: lock button, message hooks, persistence, migration |
| `tests/` | Test suite for the five Discord-free modules |

`crypto.ts`, `compress.ts`, `session.ts`, `vault.ts` and `serial.ts` have no Vencord or Discord dependencies and could be adapted for other clients.

## Tests

```sh
node tests/run.mjs
```

Node 22+ provides the same Web Crypto primitives the browser does (X25519, HKDF, AES-GCM) plus `DecompressionStream`, so the suite exercises the real implementations rather than mocks — no test doubles, no crypto stubs.

Coverage focuses on the invariants that are expensive to debug in a live conversation:

- byte-exact compression round-trips, including empty input, all 256 byte values, multi-chunk payloads and buffer views;
- no unhandled rejections left behind when a stream errors;
- a failed decryption leaves ratchet state byte-identical;
- a send overlapping a receive reuses a message key when unserialised, and does not through the queue;
- a save started mid-ratchet-step still writes one consistent snapshot;
- a rejected over-long message doesn't advance the ratchet;
- `projectedWireLength` matches real encryption output exactly;
- out-of-order delivery, the `MAX_SKIP` boundary, and replay rejection;
- the handshake converges on identical safety numbers from both sides;
- the vault fails closed on a wrong password, tampered ciphertext, tampered IV or downgraded KDF parameters.
