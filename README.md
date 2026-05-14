# Vencord E2EE

> End-to-end encryption for Discord DMs, implemented as a [Vencord](https://vencord.dev) userplugin.

Uses a **Signal-style Double Ratchet** under the hood: X25519 ECDH for key agreement, HKDF-SHA256 for key derivation, and AES-256-GCM for AEAD encryption. All cryptography runs through the browser's native **Web Crypto API** — no external JavaScript crypto libraries.

---

## How it works

1. On first run, generates a long-term X25519 identity keypair and stores it locally (Vencord's `DataStore`, backed by IndexedDB).
2. Adds a lock button (🔓/🔒) to the chat bar in DMs. Clicking it enables E2EE for that conversation.
3. The handshake is a 2-message round trip (INIT + ACK) carrying both users' identity pubkeys and one-time ephemeral pubkeys. The shared secret is derived from a 4-DH mix (mutual identity × ephemeral) — a trimmed-down X3DH.
4. Once the handshake completes, every message is run through the Double Ratchet: a fresh DH ratchet step on every conversation "turn", with a symmetric KDF chain producing a per-message AEAD key.
5. Out-of-order delivery is handled by caching skipped message keys (capped at 200 per chain).
6. Decrypted plaintext is cached locally so reloading a channel doesn't re-show ciphertext.

## What it looks like on the wire

Discord (and anyone else reading the channel) sees:

```
🔐⟨E2EE v1⟩AAECAwQF...long-base64-blob...==
```

Your local client silently renders the decrypted plaintext instead.

## Protocol summary

```
Alice → Bob:   🔐⟨E2EE-INIT v1⟩base64(IdA‖EphA)
Bob   → Alice: 🔐⟨E2EE-ACK  v1⟩base64(IdB‖EphB)
… both compute SK = HKDF(DH₁‖DH₂‖DH₃‖DH₄) …

Alice → Bob:   🔐⟨E2EE v1⟩base64(header‖ct)
Bob   → Alice: 🔐⟨E2EE v1⟩base64(header‖ct)

Either side:   🔐⟨E2EE-RESET v1⟩
```

`header` is 40 bytes: 32-byte sender ratchet pubkey + 4-byte previous-chain length + 4-byte message number. `ct` is AES-GCM output (ciphertext + 16-byte auth tag). The header is bound to the AEAD as additional data.

## Security properties

**Forward secrecy.** Past messages cannot be decrypted by an attacker who later compromises your ratchet state, because each DH ratchet step derives a fresh root key and chain key.

**Break-in recovery.** After a ratchet step, an attacker who had your old state loses the ability to decrypt future messages.

**Safety numbers.** The first handshake is trust-on-first-use (TOFU). To defend against a hypothetical MITM (e.g. a malicious Discord), both users should compare their **safety number** out of band (voice call, another channel, in person). It is displayed in a toast when the session becomes ready and in the lock button's tooltip. If your numbers match, your identity keys agree and no MITM is present.

## Limitations

- **Metadata is not protected.** Discord still sees who talks to whom, when, message sizes, channel IDs, and the fact that you are using E2EE (the marker is plaintext).
- **Local plaintext cache.** Decrypted messages are stored in IndexedDB. If you want true forward secrecy, clear the plugin's data periodically; you will lose the ability to view old messages, but the ciphertexts in Discord remain unreadable.
- **Both users need this plugin.** There is no plaintext fallback. A peer without the plugin will see only opaque base64.
- **Attachments, embeds, replies, reactions, and edits are not encrypted.** Only message text.
- **~1300 character limit.** Encrypted messages are roughly 40% larger after base64. Discord's 2000-character cap leaves room for approximately 1300 characters of plaintext. Chunking is not implemented.
- **Discord's ToS.** Client mods are technically against Discord's terms of service. Account bans for using Vencord are rare in practice but possible.

## Repository layout

| File | Purpose |
|---|---|
| `crypto.ts` | X25519/HKDF/AES-GCM primitives and Double Ratchet state machine |
| `session.ts` | Per-channel session lifecycle, handshake protocol, wire format |
| `index.tsx` | Vencord plugin: lock button, message hooks, persistence |

The crypto layer (`crypto.ts` + `session.ts`) has no Vencord or Discord dependencies and could be adapted for other clients.

## Installation

> **Both users in the DM need to install this plugin.**

1. Set up Vencord from source: <https://docs.vencord.dev/installing/custom-plugins/>
2. Drop this folder into `Vencord/src/userplugins/E2EE/`.
3. Run `pnpm build` and `pnpm inject`.
4. Open Discord, go to Vencord settings, and enable **E2EE**.
5. Restart Discord.

## Usage

1. Open a DM with a peer who also has the plugin installed.
2. Click the 🔓 button in the chat bar. It turns yellow.
3. Type a message and send. Your message will not be delivered — the plugin sends a handshake INIT instead and notifies you. Retype your message after the lock turns green (🔒).
4. The peer's plugin prompts them to accept. Once they enable E2EE and send a message, both clients show 🔒 and display a **safety number**.
5. **Compare safety numbers out of band before sending anything sensitive.**
6. Every subsequent message is encrypted end-to-end.

To disable E2EE for a DM, click 🔒. The session is destroyed and a reset marker is sent to the peer.

### Lock button states

| Icon | Meaning |
|---|---|
| 🔓 | E2EE off |
| 🟡 | Handshake in progress or E2EE enabled, awaiting first send |
| 📩 | Peer has sent a handshake invitation |
| 🔒 | Secure channel active — hover for safety number |

## Possible improvements

- **QR code for safety numbers** — render as a scannable QR code (like Signal) for easier out-of-band verification.
- **Session export / device transfer** — currently there is no way to move a session to a different machine; a fresh handshake is required.