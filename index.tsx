/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * Vencord plugin entry point.
 *
 * Wires the crypto + session layer into Discord:
 *   • A lock button on each DM toggles E2EE on/off.
 *   • Outgoing messages are intercepted by addMessagePreSendListener and
 *     replaced with their encrypted form when a session is ready.
 *   • Incoming messages are intercepted by FluxDispatcher (MESSAGE_CREATE
 *     and friends). Encrypted ones are decrypted; the plaintext is stored
 *     in a per-message cache so reloads don't show ciphertext, and the
 *     message in the Discord store is mutated in place so it renders as
 *     plaintext.
 */

import { ChatBarButton, ChatBarButtonFactory } from "@api/ChatButtons";
import { DataStore } from "@api/index";
import { MessageAccessoryFactory } from "@api/MessageAccessories";
import { MessageDecorationFactory } from "@api/MessageDecorations";
import {
    addMessagePreEditListener,
    addMessagePreSendListener,
    MessageEditListener,
    MessageSendListener,
    removeMessagePreEditListener,
    removeMessagePreSendListener,
} from "@api/MessageEvents";
import { updateMessage } from "@api/MessageUpdater";
import { definePluginSettings } from "@api/Settings";
import { FormSwitch } from "@components/FormSwitch";
import { Paragraph } from "@components/Paragraph";
import { sendMessage } from "@utils/discord";
import { Logger } from "@utils/Logger";
import definePlugin, { IconComponent, OptionType } from "@utils/types";
import type { ToastVariant } from "@vencord/discord-types";
import {
    ChannelStore, DraftType, FluxDispatcher, MessageStore, React, showToast, Tooltip,
    UploadAttachmentStore, UserStore, useStateFromStores,
} from "@webpack/common";

import { askChoice } from "./ChoiceModal";
import { b64encode, safetyNumber } from "./crypto";
import { askPassphrase } from "./PassphraseModal";
import { runExclusive, serialWriter } from "./serial";
import {
    buildAck, buildInit, decryptForSession, deserializeIdentity, deserializeSession,
    emptySession, encryptForSession, handleAck, Identity, isE2EEMessage, isLegacyE2EEMessage,
    MessageTooLongError, newIdentity, parseInit, PREFIX_ACK, PREFIX_INIT, PREFIX_MSG, PREFIX_RESET,
    SerializedIdentity, SerializedSession, serializeIdentity, serializeSession, Session,
} from "./session";
import {
    isVaultBlob, isVaultMeta, makeVaultMeta, unlockVault, vaultDecrypt, vaultEncrypt,
    VaultMeta, WrongPassphraseError,
} from "./vault";

function toast(text: string, variant: ToastVariant = "default") {
    showToast({ text, variant });
}

// ------------------------------ Logger ------------------------------

const log = new Logger("E2EE");

// ------------------------------ Persistent storage ------------------------------

/*
 * Stores split into two classes.
 *
 * SECRET stores are wrapped by the vault when at-rest encryption is on:
 *   identity   — the long-term X25519 private key
 *   sessions   — root keys, chain keys, skipped message keys
 *   decrypted  — the plaintext of every message you've read
 *
 * PUBLIC stores are never wrapped. That is a deliberate choice, not an
 * oversight: their contents (channel IDs, message IDs, peer *public* keys) tell
 * an attacker nothing the Discord account itself doesn't already reveal, and
 * `enabled` in particular has to remain readable while the vault is locked.
 * It is the only record of "this DM is supposed to be encrypted" — without it,
 * a locked plugin couldn't tell an E2EE channel from a normal one and would
 * happily let a message meant for an encrypted DM go out in the clear.
 */
const STORE_IDENTITY = "E2EE_identity_v2"; // SECRET
const STORE_SESSIONS = "E2EE_sessions_v2"; // SECRET Record<channelId, SerializedSession>
const STORE_DECRYPTED = "E2EE_decrypted_v2"; // SECRET Record<messageId, string>
const STORE_ENABLED = "E2EE_enabled_v2"; // public  Record<channelId, boolean>
const STORE_PROCESSED = "E2EE_processed_v2"; // public  string[] of handshake message IDs
const STORE_KNOWN_KEYS = "E2EE_knownKeys_v2"; // public  Record<userId, b64 identity pubkey>
const STORE_VAULT = "E2EE_vault_v2"; // public  VaultMeta

const LEGACY_STORE_IDENTITY = "E2EE_identity_v1";
const LEGACY_STORE_SESSIONS = "E2EE_sessions_v1";
const LEGACY_STORE_DECRYPTED = "E2EE_decrypted_v1";
const LEGACY_STORE_ENABLED = "E2EE_enabled_v1";
const LEGACY_STORE_PROCESSED = "E2EE_processed_v1";
const LEGACY_STORE_KNOWN_KEYS = "E2EE_knownKeys_v1";

let identity: Identity | null = null;
const sessions = new Map<string, Session>();
const decryptedCache = new Map<string, string>();
const enabledChannels = new Set<string>();
/**
 * Pinned identity pubkeys per peer user ID (TOFU key pinning). Sessions are
 * ephemeral — they die on RESET — but this map survives, so a MITM who forces
 * a reset and re-handshakes with their own key trips a loud "identity key
 * CHANGED" warning instead of silently looking like a fresh invitation.
 */
const knownPeerKeys = new Map<string, string>();
/**
 * IDs of handshake messages (INIT / ACK / RESET) we've already acted on.
 *
 * Without this, every channel-scroll / history-load fires LOAD_MESSAGES_SUCCESS
 * which feeds every message — including ancient handshake messages — back into
 * handleIncoming. An old INIT would then be (re-)processed as if it were fresh:
 * the plugin would derive a new SK, overwrite the live `ready` session, and
 * fire off a stray ACK into the channel, destroying the active secure channel.
 *
 * Tracking message IDs and short-circuiting before any state mutation keeps
 * historical handshake messages purely cosmetic on reload. We persist this set
 * so a client restart can't replay them either.
 */
const processedHandshakeMsgs = new Set<string>();

/**
 * Plaintext of our own outgoing encrypted messages, keyed by the exact wire
 * string we sent. We can't decrypt our own ciphertext (the ratchet only moves
 * forward), and at pre-send time the message has no ID yet — so we stash the
 * plaintext here and copy it into `decryptedCache` (keyed by the real message
 * ID) when the server echoes our message back via MESSAGE_CREATE. Without
 * this, your own messages would render as an "[encrypted]" placeholder
 * forever. Not persisted: it only needs to survive the send → echo window.
 *
 * Entries are NOT removed on first use. Discord announces one send several
 * times — the optimistic local echo, the gateway MESSAGE_CREATE, MESSAGE_SUCCESS,
 * and any later MESSAGE_UPDATE — and each pass has to resolve to the same
 * plaintext. Consuming the entry on the first pass made every later pass fall
 * through to the "[encrypted — sent]" placeholder, which is what the user
 * actually ends up looking at. The MAX_PENDING_OWN cap is what frees entries.
 */
const pendingOwnPlaintext = new Map<string, string>();
const MAX_PENDING_OWN = 200;

/** Drop the oldest entries of an insertion-ordered collection past `max`. */
function trimOldest(collection: Map<string, unknown> | Set<string>, max: number) {
    for (const key of collection.keys()) {
        if (collection.size <= max) break;
        collection.delete(key);
    }
}

/** Stash our own plaintext, evicting the oldest entries past the cap. */
function rememberOwnPlaintext(wire: string, plaintext: string) {
    pendingOwnPlaintext.delete(wire); // re-insert so it counts as newest
    pendingOwnPlaintext.set(wire, plaintext);
    trimOldest(pendingOwnPlaintext, MAX_PENDING_OWN);
}

/** Look up our own plaintext for a wire string, refreshing its position so a
 *  message that is still being re-dispatched can't be evicted underneath us. */
function recallOwnPlaintext(wire: string): string | undefined {
    const pt = pendingOwnPlaintext.get(wire);
    if (pt === undefined) return undefined;
    pendingOwnPlaintext.delete(wire);
    pendingOwnPlaintext.set(wire, pt);
    return pt;
}

/**
 * Ciphertext of our own in-flight messages, keyed by the optimistic (local)
 * message ID Discord assigns to the echo it renders before the server replies.
 * We rewrite that echo to plaintext so you see what you typed — but if the
 * send then fails, the failed message stays in the store and Discord's retry
 * re-sends its content. Putting the ciphertext back on MESSAGE_SEND_FAILED
 * keeps a retry from shipping that plaintext in the clear.
 */
const inFlightWire = new Map<string, string>();
const MAX_IN_FLIGHT = 50;

/**
 * Optimistic IDs of sends that failed. The failure can be announced before the
 * queued rewrite of that same optimistic echo has run; without this record the
 * late rewrite would put the plaintext back into a message whose Retry button
 * re-sends whatever it holds.
 */
const failedSends = new Set<string>();

/**
 * IDs of messages that arrived in an E2EE-enabled DM without being encrypted.
 * The lock badge only appears on the first message of a group, so a plaintext
 * message slipped in right after an encrypted one would sit under a header that
 * says "encrypted". These get their own notice on the message itself.
 */
const unencryptedInSecureChat = new Set<string>();
const MAX_UNENCRYPTED_FLAGS = 500;

/**
 * Copies of E2EE messages that arrived while the vault was locked, keyed by
 * message ID. Their store copies are overwritten with a placeholder, so the
 * original has to be kept somewhere for the unlock to have anything to decrypt.
 */
const lockedMessages = new Map<string, { channelId: string; message: any; }>();
const MAX_LOCKED_MESSAGES = 500;

/** Cap so the persisted plaintext cache can't grow without bound.
 *  Maps iterate in insertion order, so this evicts the oldest entries. */
const MAX_DECRYPTED_CACHE = 5000;
/** The cache holds plaintext that has not been written to disk yet. */
let decryptedDirty = false;
/** A received message changed state in memory and `persistState` is still owed. */
let unsavedIncoming = false;
function cacheDecrypted(messageId: string, plaintext: string) {
    decryptedCache.set(messageId, plaintext);
    trimOldest(decryptedCache, MAX_DECRYPTED_CACHE);
    decryptedDirty = true;
    unsavedIncoming = true;
}

// React subscribers that want to re-render when E2EE state changes.
// `sessions` and `enabledChannels` are plain module-level mutables, invisible
// to React, so any code that mutates them must call notifyStateChange() to
// nudge subscribed components (e.g. LockButton) to re-render. Without this,
// the lock icon wouldn't update until the user switched channels and Discord
// happened to re-mount the button.
const stateSubscribers = new Set<() => void>();
function notifyStateChange() {
    for (const fn of stateSubscribers) {
        try { fn(); } catch (e) { log.warn("state subscriber threw", e); }
    }
}

// ------------------------------ Vault (encryption at rest) ------------------------------

/** Derived from the user's passphrase; null when at-rest encryption is off. */
let vaultKey: CryptoKey | null = null;
/** True when stored data IS encrypted but we couldn't decrypt it (the user
 *  dismissed the unlock prompt). The plugin then runs in a degraded read-only
 *  mode: no identity, no sessions, and — critically — no plaintext sends. */
let vaultLocked = false;
/**
 * Whether stored data is actually encrypted, i.e. whether vault metadata
 * exists. This — not a saved boolean — is what the settings toggle displays;
 * see `EncryptAtRestSetting` for why that distinction matters.
 */
let vaultActive = false;
/**
 * True once the SECRET stores have been read into memory. Until then the
 * in-memory maps are empty for a reason other than "there is no data" — the
 * plugin has not started, or the unlock failed part-way — and saving them
 * would replace real sessions and messages with nothing.
 */
let secretsLoaded = false;

/** Read a SECRET store, transparently unwrapping it if it's vault-encrypted. */
async function readSecret<T>(key: string): Promise<T | undefined> {
    const raw = await DataStore.get<unknown>(key);
    if (raw === undefined) return undefined;
    if (isVaultBlob(raw)) {
        if (!vaultKey) throw new Error(`${key} is encrypted but the vault is locked`);
        return await vaultDecrypt<T>(vaultKey, raw);
    }
    // Plaintext record: either at-rest encryption is off, or this store hasn't
    // been rewritten since it was turned on. Either way it reads fine, and the
    // next write will encrypt it.
    return raw as T;
}

/** Write a SECRET store, wrapping it if the vault is unlocked and in use. */
async function writeSecret(key: string, value: unknown): Promise<void> {
    // Refusing to write while locked is what keeps a dismissed unlock prompt
    // from being destructive. In that state every in-memory map is empty, so an
    // unguarded write would serialise "no identity, no sessions, no cached
    // messages" straight over the user's real (encrypted) data. The same goes
    // for any other moment the maps have not been loaded yet.
    if (vaultLocked || !secretsLoaded) return;
    await DataStore.set(key, vaultKey ? await vaultEncrypt(vaultKey, value) : value);
}

/**
 * Carry v1 data forward.
 *
 * The identity keypair and the pinned peer keys are plain X25519 material with
 * no protocol version baked into them, so they migrate as-is. That matters:
 * regenerating the identity on upgrade would make every peer's client shout
 * "identity key CHANGED" — training users to click through the exact warning
 * that is supposed to mean "possible MITM".
 *
 * v1 *sessions* are deliberately dropped. Their ratchet state is only valid
 * under v1's AEAD additional-data string, and the peer will be upgrading at a
 * different time anyway, so a clean re-handshake is the only coherent outcome.
 * `enabled` survives, so those DMs simply re-handshake on the next message.
 *
 * The v1 records are deleted afterwards rather than left as a backup: they
 * include the identity private key in the clear, and leaving a plaintext copy
 * behind would quietly defeat at-rest encryption for anyone who turns it on.
 */
async function migrateLegacyStores() {
    if (await DataStore.get(STORE_IDENTITY) !== undefined) return; // already on v2

    const legacyIdentity = await DataStore.get<SerializedIdentity>(LEGACY_STORE_IDENTITY);
    if (!legacyIdentity) return; // fresh install

    log.info("Migrating v1 data to protocol v2");

    await DataStore.set(STORE_IDENTITY, legacyIdentity);

    const legacyKnown = await DataStore.get<Record<string, string>>(LEGACY_STORE_KNOWN_KEYS);
    if (legacyKnown) await DataStore.set(STORE_KNOWN_KEYS, legacyKnown);

    const legacyDecrypted = await DataStore.get<Record<string, string>>(LEGACY_STORE_DECRYPTED);
    if (legacyDecrypted) await DataStore.set(STORE_DECRYPTED, legacyDecrypted);

    const legacyEnabled = await DataStore.get<Record<string, boolean>>(LEGACY_STORE_ENABLED);
    if (legacyEnabled) await DataStore.set(STORE_ENABLED, legacyEnabled);

    // STORE_PROCESSED is not carried over on purpose: v1 handshake messages no
    // longer reach any state-mutating branch (they're caught by the legacy
    // check in handleIncoming), so the de-dupe set has nothing left to protect.

    for (const key of [
        LEGACY_STORE_IDENTITY, LEGACY_STORE_SESSIONS, LEGACY_STORE_DECRYPTED,
        LEGACY_STORE_ENABLED, LEGACY_STORE_PROCESSED, LEGACY_STORE_KNOWN_KEYS,
    ]) {
        await DataStore.del(key);
    }

    log.info("Migration complete — existing DMs will re-handshake under v2");
}

/** Prompt for the passphrase until it verifies or the user gives up. */
async function promptUnlock(meta: VaultMeta): Promise<CryptoKey | null> {
    let derived: CryptoKey | null = null;
    const answered = await askPassphrase("unlock", async passphrase => {
        try {
            derived = await unlockVault(passphrase, meta);
            return null;
        } catch (e) {
            derived = null;
            if (e instanceof WrongPassphraseError) return "That password isn't right. Try again.";
            log.error("Vault unlock failed", e);
            return `Could not unlock: ${e}`;
        }
    });
    return answered === null ? null : derived;
}

async function loadAll() {
    await migrateLegacyStores();

    // Public stores first and unconditionally — see the STORE_* comments for
    // why `enabled` must be available even when we can't decrypt anything.
    const enRaw = await DataStore.get<Record<string, boolean>>(STORE_ENABLED) ?? {};
    for (const [chId, on] of Object.entries(enRaw)) if (on) enabledChannels.add(chId);

    const procRaw = await DataStore.get<string[]>(STORE_PROCESSED) ?? [];
    for (const id of procRaw) processedHandshakeMsgs.add(id);

    const keysRaw = await DataStore.get<Record<string, string>>(STORE_KNOWN_KEYS) ?? {};
    for (const [uId, k] of Object.entries(keysRaw)) knownPeerKeys.set(uId, k);

    // The presence of vault metadata — not the setting — is what decides
    // whether the data is encrypted. The setting records intent and can drift
    // from reality if a migration was interrupted; the metadata cannot.
    const meta = await DataStore.get<unknown>(STORE_VAULT);
    if (isVaultMeta(meta)) {
        vaultActive = true;

        // Locked *first*, prompt second. `start()` continues immediately and
        // installs the message hooks, so the flag has to be set before any send
        // can reach them — otherwise there would be a window where an E2EE
        // channel had no session and no lock flag, which is precisely the shape
        // that leaks plaintext.
        vaultLocked = true;
        notifyStateChange();

        // Deliberately not awaited. Blocking plugin start on a modal would
        // stall Vencord's startup, and the modal needs Discord's UI mounted to
        // render at all — which it may not be this early. If the prompt never
        // appears, the 🔑 lock button is the retry path.
        unlockAndLoad(meta).catch(e => log.error("Unlock failed", e));
        return;
    }

    await loadSecrets();
    await ensureIdentity();
}

/** Prompt for the passphrase and, on success, load what the locked start
 *  skipped. Leaves the plugin locked if the user declines. */
async function unlockAndLoad(meta: VaultMeta): Promise<boolean> {
    const key = await promptUnlock(meta);
    if (!key) {
        log.warn("E2EE data left locked — no identity or sessions loaded");
        return false;
    }

    // The lock comes off only once everything has been read. If a store turns
    // out to be unreadable the plugin stays locked, which keeps refusing both
    // sends and writes, instead of running unlocked on half-loaded state.
    vaultKey = key;
    try {
        await loadSecrets();
    } catch (e) {
        vaultKey = null;
        log.error("Could not read the saved E2EE data", e);
        toast("🔐 Your password was right, but the saved data could not be read. See the console for details.", "critical");
        return false;
    }
    vaultLocked = false;
    await ensureIdentity();

    replayLockedMessages();
    notifyStateChange();
    return true;
}

/** Load the SECRET stores. Only ever called with the vault unlocked (or absent),
 *  which is what stops a locked start from generating a fresh identity and
 *  silently orphaning every existing session. */
async function loadSecrets() {
    const idRaw = await readSecret<SerializedIdentity>(STORE_IDENTITY);
    const sessRaw = await readSecret<Record<string, SerializedSession>>(STORE_SESSIONS) ?? {};
    const decRaw = await readSecret<Record<string, string>>(STORE_DECRYPTED) ?? {};

    if (idRaw) identity = await deserializeIdentity(idRaw);

    for (const [chId, s] of Object.entries(sessRaw)) {
        try { sessions.set(chId, await deserializeSession(s)); }
        catch (e) { log.warn("Bad stored session for", chId, e); }
    }

    for (const [mId, pt] of Object.entries(decRaw)) decryptedCache.set(mId, pt);

    secretsLoaded = true;
}

/** First run: there is no identity yet, so make one. Runs after `loadSecrets`
 *  and with the vault unlocked, so the new key can actually be saved. */
async function ensureIdentity() {
    if (identity) return;
    identity = await newIdentity();
    await persistIdentity();
    log.info("Generated new identity keypair");
}

async function persistIdentity() {
    if (!identity) return;
    await writeSecret(STORE_IDENTITY, await serializeIdentity(identity));
}

/**
 * Save the sessions and, if it changed, the plaintext cache.
 *
 * Both are read in the same synchronous step and the plaintext is written
 * first. A session that has consumed a message key must never reach disk ahead
 * of that message's plaintext: the key cannot be derived a second time, so a
 * crash in between would leave the message unreadable for good. Written the
 * other way round, a crash only means decrypting it again.
 */
const persistState = serialWriter(async () => {
    const plaintext = decryptedDirty ? Object.fromEntries(decryptedCache) : null;
    decryptedDirty = false;
    const pending = Array.from(sessions, async ([id, s]) => [id, await serializeSession(s)] as const);

    try {
        if (plaintext) await writeSecret(STORE_DECRYPTED, plaintext);
    } catch (e) {
        decryptedDirty = true;
        throw e;
    }
    await writeSecret(STORE_SESSIONS, Object.fromEntries(await Promise.all(pending)));
});

async function persistEnabled() {
    const out: Record<string, boolean> = {};
    for (const id of enabledChannels) out[id] = true;
    await DataStore.set(STORE_ENABLED, out);
}

// ------------------------------ Vault setup / teardown ------------------------------

/** Retry the unlock after a dismissed prompt (the 🔑 lock button). */
async function unlockNow(): Promise<boolean> {
    const meta = await DataStore.get<unknown>(STORE_VAULT);
    if (!isVaultMeta(meta)) {
        // Nothing is actually encrypted — clear the flag so we stop refusing.
        vaultLocked = false;
        notifyStateChange();
        return true;
    }

    if (!await unlockAndLoad(meta)) return false;
    toast("🔐 Unlocked — your encrypted messages are readable again.", "success");
    return true;
}

async function enableVault() {
    if (await DataStore.get(STORE_VAULT) !== undefined) return; // already on

    if (vaultLocked) {
        toast("🔐 Unlock your saved messages first.", "critical");
        return;
    }

    // The settings panel also opens for a plugin that is switched off. Nothing
    // has been loaded then, and re-saving "everything" under the new password
    // would overwrite the real sessions and messages with empty ones.
    if (!secretsLoaded) {
        toast("🔐 Turn the E2EE plugin on first, then set a password.", "critical");
        return;
    }

    // No verification step at creation time — any passphrase meeting the
    // length minimum is acceptable, and the modal handles the confirm field.
    const passphrase = await askPassphrase("create", async () => null);
    if (passphrase === null) {
        // Cancelled. `vaultActive` was never set, so the toggle springs back
        // to off on the next render — no stored value to unwind.
        toast("🔐 Password setup cancelled — nothing was changed.");
        return;
    }

    const { meta, key } = await makeVaultMeta(passphrase);
    vaultKey = key;

    // Metadata is published BEFORE the data is rewritten, so that an
    // interruption fails in the recoverable direction. Metadata present with
    // still-plaintext stores is self-healing: the next start asks for the
    // passphrase, `readSecret` passes the plaintext records through untouched,
    // and the next write encrypts them. The reverse order would leave
    // encrypted blobs with no metadata to derive a key from — unreadable.
    await DataStore.set(STORE_VAULT, meta);
    await persistIdentity();
    decryptedDirty = true;
    await persistState();
    vaultActive = true;

    toast("🔐 Your saved messages are now password-protected. You'll be asked for the password when Discord starts.", "success");
}

async function disableVault() {
    if (await DataStore.get(STORE_VAULT) === undefined) return; // already off

    if (vaultLocked || !vaultKey) {
        if (!await unlockNow()) {
            toast("🔐 Enter your password first to turn this off.", "critical");
            return;
        }
    }

    // Drop the key first so the persist helpers emit plaintext.
    vaultKey = null;
    await persistIdentity();
    decryptedDirty = true;
    await persistState();
    await DataStore.del(STORE_VAULT);
    vaultActive = false;

    toast("🔐 Password protection turned off. Your saved messages are no longer protected on this computer.");
}

/**
 * The at-rest encryption toggle.
 *
 * Rendered as a COMPONENT rather than a BOOLEAN on purpose. Vencord's
 * `BooleanSetting` seeds a local `useState` from the stored value once and
 * never re-reads it, so cancelling the password prompt would revert the stored
 * value while leaving the switch visibly ON until the panel was reopened. For a
 * security setting that is the worst possible failure — it would tell the user
 * their messages are protected when they are not.
 *
 * Driving the switch off `vaultActive` (does vault metadata exist?) removes the
 * problem at the root: there is no second copy of the truth to drift, and
 * cancelling simply leaves the switch where it was.
 */
const EncryptAtRestSetting = () => {
    const [, setTick] = React.useState(0);
    const [busy, setBusy] = React.useState(false);

    React.useEffect(() => {
        const fn = () => setTick(t => t + 1);
        stateSubscribers.add(fn);
        return () => { stateSubscribers.delete(fn); };
    }, []);

    return (
        <FormSwitch
            title="Password-protect saved messages"
            description={
                "Locks the messages this plugin has saved on your computer behind a password, " +
                "so nobody who uses this computer can read them. You'll enter it once each time Discord starts. " +
                "If you forget it, every message you've sent or received with this plugin is lost for good — there is no reset."
            }
            value={vaultActive}
            disabled={busy}
            onChange={want => {
                setBusy(true);
                (async () => {
                    try {
                        if (want) await enableVault();
                        else await disableVault();
                    } catch (e) {
                        log.error("Vault reconfiguration failed", e);
                        toast(`🔐 Could not change the password setting: ${e}`, "critical");
                    } finally {
                        setBusy(false);
                        notifyStateChange();
                    }
                })();
            }}
        />
    );
};

async function persistProcessed() {
    await DataStore.set(STORE_PROCESSED, Array.from(processedHandshakeMsgs));
}

/** Record that a handshake message has been processed so future bulk loads
 *  treat it as inert history rather than a fresh signal. */
async function markProcessed(messageId: string) {
    if (!messageId) return;
    if (processedHandshakeMsgs.has(messageId)) return;
    processedHandshakeMsgs.add(messageId);
    await persistProcessed();
}

// ------------------------------ Peer identity key pinning ------------------------------

/** Compare an identity pubkey seen in a handshake against the pinned one. */
function checkPeerKey(userId: string, idPub: Uint8Array): "new" | "match" | "changed" {
    const known = knownPeerKeys.get(userId);
    if (!known) return "new";
    return known === b64encode(idPub) ? "match" : "changed";
}

/** Pin (or re-pin) a peer's identity pubkey. Called whenever a handshake
 *  completes — i.e. only after either an explicit user accept on our side or
 *  a key-change warning has already been shown. */
async function pinPeerKey(userId: string, idPub: Uint8Array) {
    const b64 = b64encode(idPub);
    if (knownPeerKeys.get(userId) === b64) return;
    knownPeerKeys.set(userId, b64);
    await DataStore.set(STORE_KNOWN_KEYS, Object.fromEntries(knownPeerKeys));
}

/** The peer's user ID in a 1:1 DM channel. */
function getPeerUserId(channelId: string): string | null {
    const ch = ChannelStore.getChannel(channelId);
    return ch?.recipients?.[0] ?? null;
}

// ------------------------------ Handshake actions ------------------------------

/** Initiator side: generate an ephemeral key and send the INIT immediately.
 *  Callers show their own context-appropriate toast. */
async function startHandshake(channelId: string) {
    if (!identity) return;
    const { wire, eph } = await buildInit(identity);
    sessions.set(channelId, { ...emptySession(), phase: "init-sent", pendingEph: eph });
    await persistState();
    notifyStateChange();
    sendRaw(channelId, wire);
}

/** True if this session's peer key differs from the one pinned for the peer. */
function hasChangedKey(channelId: string, s: Session): boolean {
    const peerId = getPeerUserId(channelId);
    return !!peerId && !!s.peerIdPub && checkPeerKey(peerId, s.peerIdPub) === "changed";
}

/**
 * Send the first encrypted message of a new session.
 *
 * By Double Ratchet design the responder has no sending chain until the
 * initiator's first encrypted message reaches them and triggers their DH
 * ratchet, so until we send something all of their sends would fail. It
 * decrypts to a visible "channel established" note on their end.
 */
async function sendPrime(channelId: string, s: Session) {
    const text = "🔐 Secure channel established.";
    const wire = await encryptForSession(s, text);
    rememberOwnPlaintext(wire, text);
    await persistState();
    sendRaw(channelId, wire);
}

/** Turn E2EE off for a DM and tell the peer, unless they are the one who ended it. */
async function turnOff(channelId: string) {
    const previous = sessions.get(channelId);
    enabledChannels.delete(channelId);
    sessions.delete(channelId);
    await persistEnabled();
    await persistState();
    notifyStateChange();
    if (previous && previous.phase !== "none" && previous.phase !== "peer-reset") sendRaw(channelId, PREFIX_RESET);
}

/** Responder side: accept a pending invitation — derive the session, pin the
 *  peer's identity key, and send the ACK. Returns the ready session, or null
 *  on failure (failure toasts are shown here; success toasts by the caller). */
async function acceptInvite(channelId: string, s: Session): Promise<Session | null> {
    if (!identity) return null;
    if (!s.peerIdPub || !s.peerEphPub) {
        log.error("init-recvd phase missing peer keys", channelId);
        sessions.delete(channelId);
        await persistState();
        notifyStateChange();
        toast("🔐 Handshake failed — invitation was corrupt.", "critical");
        return null;
    }
    try {
        const { wire, session: newSession } = await buildAck(identity, s.peerIdPub, s.peerEphPub);
        sessions.set(channelId, newSession);
        await persistState();
        const peerId = getPeerUserId(channelId);
        if (peerId) await pinPeerKey(peerId, s.peerIdPub);
        notifyStateChange();
        sendRaw(channelId, wire);
        return newSession;
    } catch (e) {
        log.error("Failed to build ACK", e);
        toast("🔐 Handshake failed.", "critical");
        return null;
    }
}

// ------------------------------ Outgoing message hook ------------------------------

const onSend: MessageSendListener = async (channelId, msg, _options, props) => {
    // Don't molest our own handshake markers, etc. (any protocol version).
    if (isE2EEMessage(msg.content)) return;

    if (!enabledChannels.has(channelId)) return;

    const ch = ChannelStore.getChannel(channelId);
    if (!ch || !isDM(ch)) return; // Only DMs are supported.

    // Past this point the channel is E2EE-enabled, so the message must either
    // be encrypted or cancelled. That includes failures: Vencord logs a
    // listener that throws and then sends the message as typed, so an error
    // escaping from here would put the plaintext on the wire.
    //
    // The work runs in the channel's queue, behind any message currently being
    // decrypted. An encrypt that overlaps a decrypt is how a message key gets
    // used twice (see serial.ts).
    try {
        const result = await runExclusive(channelId, () => sendEncrypted(channelId, msg));
        // Warn only: files go to Discord as they are, and blocking them would
        // take away the only way to send one at all.
        if (!result?.cancel && props?.hasAttachments) {
            toast("⚠️ Your text was encrypted, but the attached file was NOT. Discord can see it.", "critical");
        }
        return result;
    } catch (e) {
        log.error("Send hook failed", e);
        toast("🔐 Something went wrong, so your message was not sent. It is still in the box.", "critical");
        return { cancel: true };
    }
};

async function sendEncrypted(channelId: string, msg: { content: string; }): Promise<{ cancel: boolean; } | void> {
    // The lock may have been turned off while this send was waiting its turn.
    // Sending now would be unencrypted, which is not what Enter meant when it
    // was pressed, so ask for a second one.
    if (!enabledChannels.has(channelId)) {
        toast("🔐 Encryption was just turned off here. Press Enter again to send without it.");
        return { cancel: true };
    }

    if (vaultLocked) {
        toast(
            "🔐 Locked. Click the 🔑 button and enter your password before sending here.",
            "critical"
        );
        return { cancel: true };
    }

    if (!identity) {
        toast("🔐 E2EE isn't ready yet — try again in a moment.", "critical");
        return { cancel: true };
    }

    const s = sessions.get(channelId) ?? emptySession();

    // A cancelled send leaves the text in the message box, so every refusal
    // below tells the user to press Enter again rather than to retype.

    if (s.phase === "peer-reset") {
        toast(
            "🔐 Your friend ended the encrypted chat, so nothing was sent. " +
            "Click the ⚠️ button to choose what happens next.",
            "critical"
        );
        return { cancel: true };
    }

    // No session yet? Kick off handshake. Normally the lock click already did
    // this; the path remains for a channel that is enabled without a session.
    if (s.phase === "none") {
        await startHandshake(channelId);
        toast("🔐 Invitation sent. Your message is still in the box — press Enter again once the button shows 🔒.");
        return { cancel: true };
    }

    if (s.phase === "init-sent") {
        // Still waiting on the peer's ACK. Refuse to send plaintext.
        toast("🔐 Still waiting for your friend to accept. Press Enter again once the button shows 🔒.");
        return { cancel: true };
    }

    if (s.phase === "init-recvd") {
        // A changed identity key is never accepted as a side effect of typing.
        if (hasChangedKey(channelId, s)) {
            toast(
                "⚠️ Nothing was sent: your friend's identity key has changed. Click the ⚠️ button to review it.",
                "critical"
            );
            return { cancel: true };
        }

        // Pending invitation in an already-enabled channel (the INIT arrived
        // after the user turned the lock on, so the lock click couldn't accept
        // it). Sending a message is the explicit accept gesture here. The
        // message itself has to wait: as responder we can't encrypt until the
        // peer's first encrypted message primes our sending chain.
        const sess = await acceptInvite(channelId, s);
        if (sess) {
            const safety = settings.store.showSafetyNumberOnReady
                ? ` Safety #: ${sess.safetyNum}.`
                : "";
            toast(
                `🔐 Invitation accepted.${safety} ` +
                "Your message is still in the box — press Enter again in a moment.",
                "success"
            );
        }
        return { cancel: true };
    }

    if (s.untrustedKey) {
        toast(
            "⚠️ Nothing was sent: your friend's identity key has changed. Click the ⚠️ button to review it.",
            "critical"
        );
        return { cancel: true };
    }

    // Phase === "ready" — encrypt.
    try {
        const plaintext = msg.content;
        const wire = await encryptForSession(s, plaintext);
        // The ratchet advances on every send, and the advanced state has to be
        // on disk before the message leaves: restarting from older state would
        // seal the next message under this one's key.
        await persistState();
        msg.content = wire;
        // Remember our own plaintext so the echoed message renders readably.
        rememberOwnPlaintext(wire, plaintext);
    } catch (e) {
        // Too long to fit in one Discord message. `encryptForSession` raises
        // this before touching the ratchet, so there is nothing to roll back —
        // the user can shorten the text and send again with no gap in the
        // message numbering the peer sees.
        if (e instanceof MessageTooLongError) {
            toast(
                `🔐 Too long to send encrypted: ${e.wireLength}/${e.maxLength} characters once encrypted. ` +
                `Remove about ${e.approxCharsToRemove} characters, or split it into two messages.`,
                "critical"
            );
            return { cancel: true };
        }

        log.error("Encrypt failed", e);
        // As the handshake responder we cannot send until the peer's first
        // encrypted message arrives and primes our sending chain (the peer's
        // client sends one automatically on ACK receipt).
        toast(
            String(e).includes("no sending chain")
                ? "🔐 Waiting for the peer's first encrypted message — try again in a moment."
                : "🔐 Encryption failed; aborting send.",
            "critical"
        );
        return { cancel: true };
    }
}

// ------------------------------ Outgoing edit hook ------------------------------

/**
 * Edits go through Discord's edit path, which addMessagePreSendListener does
 * NOT cover — without this hook, editing one of your own encrypted messages
 * would ship the new content in PLAINTEXT. Re-encrypting an edit isn't useful
 * either (the ratchet can't re-key an old message; the peer would decrypt it
 * out of order), so edits are simply blocked in E2EE channels.
 */
const onEdit: MessageEditListener = (channelId, messageId) => {
    const ch = ChannelStore.getChannel(channelId);
    if (!ch || !isDM(ch)) return;

    // The store's copy of an E2EE message has already been rewritten by
    // replaceContent, so we can't just look for ciphertext: decrypted messages
    // are tracked in decryptedCache, and everything else we rendered (raw
    // ciphertext, placeholders, handshake markers) starts with the 🔐 marker.
    const original = MessageStore.getMessage(channelId, messageId);
    const wasE2EE = decryptedCache.has(messageId)
        || isE2EEMessage(original?.content ?? "")
        || (original?.content ?? "").startsWith("🔐");

    if (!enabledChannels.has(channelId) && !wasE2EE) return;

    toast(
        "🔐 Edit blocked: edits are not encrypted and would leak plaintext. Send a new message instead.",
        "critical"
    );
    return { cancel: true };
};

// ------------------------------ Incoming message hook ------------------------------

/**
 * @param optimistic True for the local echo Discord renders immediately after
 *   you hit enter, before the server has confirmed anything. Its message ID is
 *   client-side and gets thrown away once the gateway echo arrives, so such a
 *   message may be rendered but must never have anything persisted under its
 *   ID (neither decrypted plaintext nor the processed-handshake set).
 */
async function handleIncoming(channelId: string, message: any, optimistic = false): Promise<void> {
    if (!message?.content) return;
    const content: string = message.content;
    if (!isE2EEMessage(content)) return;

    const ch = ChannelStore.getChannel(channelId);
    if (!ch || !isDM(ch)) return;

    // This send already failed and had its ciphertext restored. Leave it alone
    // so Retry cannot re-send a plaintext we rendered into it.
    if (optimistic && failedSends.has(message.id)) return;

    // A v1 marker: either our own pre-upgrade history or a peer who hasn't
    // updated. v2 key derivation is domain-separated from v1, so there is no
    // way to read these — but labelling them beats rendering base64, and it
    // tells the user what to ask the peer to do.
    if (isLegacyE2EEMessage(content)) {
        replaceContent(
            channelId, message,
            "🔐 [E2EE v1 message — this build speaks v2 only. If the peer is on v1, both of you need to update and re-handshake.]"
        );
        return;
    }

    // Locked vault: we can see that this is one of ours but hold no keys.
    // Render a placeholder and touch nothing — in particular do not mark
    // handshake messages processed, so they still take effect after unlocking.
    // The placeholder overwrites the store's copy, so keep the original: it is
    // what `replayLockedMessages` feeds back through here after the unlock.
    if (vaultLocked) {
        if (!optimistic && message.id) {
            lockedMessages.set(message.id, { channelId, message: { ...message } });
            trimOldest(lockedMessages, MAX_LOCKED_MESSAGES);
        }
        replaceContent(channelId, message, "🔐 [Locked — enter your password to read this message]");
        return;
    }

    if (!identity) return;

    // Don't try to "decrypt" our own outgoing handshake / ciphertext (we
    // produced it, and our session state for sending is already advanced).
    // If we can't tell who authored the message (MESSAGE_UPDATE payloads may
    // omit `author`), bail rather than risk feeding our OWN ciphertext into
    // the ratchet — its unknown header pubkey would trigger a bogus DH
    // ratchet and wreck the session.
    const me = UserStore.getCurrentUser();
    if (!me?.id || !message.author?.id) return;
    const fromSelf = message.author.id === me.id;

    // Remember what we're about to render over, so a failed send can be put
    // back on the wire (see inFlightWire).
    if (optimistic && fromSelf && message.id) {
        inFlightWire.delete(message.id);
        inFlightWire.set(message.id, content);
        trimOldest(inFlightWire, MAX_IN_FLIGHT);
    }

    /** markProcessed, but a no-op for optimistic echoes: their IDs are
     *  throwaway, and persisting them would grow the set forever without ever
     *  matching a real message. The gateway copy marks the real ID. */
    const markProcessedIfReal = (id: string) =>
        optimistic ? Promise.resolve() : markProcessed(id);

    // For handshake messages (INIT / ACK / RESET) we de-dupe by message ID:
    // any given handshake message must take its state-mutating effect at most
    // once, ever. This is what protects us from LOAD_MESSAGES_SUCCESS feeding
    // a stale INIT (or our own old RESET) back into this function and tearing
    // down a live `ready` session.
    const isHandshake =
        content.startsWith(PREFIX_INIT) ||
        content.startsWith(PREFIX_ACK) ||
        content.startsWith(PREFIX_RESET);
    const alreadyProcessed = isHandshake && processedHandshakeMsgs.has(message.id);

    try {
        if (content.startsWith(PREFIX_INIT)) {
            if (fromSelf) {
                // Our own outgoing INIT — purely cosmetic on render.
                replaceContent(channelId, message, "🔐 [E2EE handshake invitation sent]");
                await markProcessedIfReal(message.id);
                return;
            }
            if (alreadyProcessed) {
                // Old INIT loaded from history; we already acted on it (or
                // explicitly decided not to). Render but do NOT mutate state.
                //
                // "Acted on it" includes merely stashing it as a pending
                // invitation, which is what a restart looks like: the session
                // survives in storage while the message re-renders from
                // scratch. That invitation is still live and acceptable, so
                // don't call it historic. Match on the ephemeral key so only
                // THIS INIT gets the live label — an older, superseded one
                // still reads as historic.
                const current = sessions.get(channelId);
                let stillPending = false;
                let keyChanged = false;
                if (current?.phase === "init-recvd" && current.peerEphPub) {
                    try {
                        const parsed = parseInit(content);
                        stillPending = b64encode(parsed.peerEphPub) === b64encode(current.peerEphPub);
                        // A pending invitation's key is never pinned (pinning
                        // happens on accept), so this still reports "changed"
                        // across a restart — keep the warning attached to the
                        // message rather than silently downgrading it.
                        keyChanged = stillPending
                            && checkPeerKey(message.author.id, parsed.peerIdPub) === "changed";
                    } catch {
                        // Malformed body — fall through to the historic label.
                    }
                }
                replaceContent(
                    channelId, message,
                    stillPending
                        ? inviteLabel(keyChanged, current?.safetyNum ?? null)
                        : "🔐 [E2EE handshake invitation — historic]"
                );
                return;
            }

            const { peerIdPub, peerEphPub } = parseInit(content);
            const current = sessions.get(channelId);

            // Refuse to overwrite ANY non-trivial session state with an
            // unsolicited INIT. A hostile peer (or a confused legitimate peer)
            // sending a fresh INIT must not be able to:
            //   - silently rotate keys out from under an established `ready` channel
            //   - abort our in-flight `init-sent` handshake and impersonate the responder
            //   - race a legitimate peer's `init-recvd` invitation by overwriting it
            // The user can reset manually (lock off → lock on) if they want to
            // accept a fresh handshake. A channel the peer reset has no session
            // left to protect, so there an invitation is welcome.
            if (current && current.phase !== "none" && current.phase !== "peer-reset") {
                const reason =
                    current.phase === "ready" ? "secure channel already active" :
                    current.phase === "init-sent" ? "outgoing handshake in flight" :
                    /* init-recvd */ "another invitation already pending";
                replaceContent(channelId, message, `🔐 [E2EE handshake invitation ignored — ${reason}]`);
                toast(
                    `🔐 Peer sent a handshake invitation, but ${reason}. ` +
                    "Toggle the lock off and on to reset if you want to accept it."
                );
                await markProcessedIfReal(message.id);
                return;
            }

            // TOFU pin check: a fresh INIT carrying a different identity key
            // than the one we've pinned for this user is exactly what a MITM
            // (or a peer who wiped their data) looks like. We still stash the
            // invitation — the user decides — but the warning must be loud.
            const keyChanged = checkPeerKey(message.author.id, peerIdPub) === "changed";

            // Stash the INIT as a pending invitation. We do NOT auto-reply
            // here — that was the spam vector. The user must explicitly accept
            // (click the lock, or send a message if already enabled), which
            // runs buildAck and produces the actual ACK wire.
            //
            // The safety number is worked out now rather than on accept: it
            // only needs the two identity keys, and "compare it before you
            // accept" is advice nobody can follow if it appears afterwards.
            const pending: Session = {
                ...emptySession(),
                phase: "init-recvd",
                peerIdPub,
                peerEphPub,
                safetyNum: await safetyNumber(identity.publicKey, peerIdPub),
            };
            sessions.set(channelId, pending);
            await persistState();
            notifyStateChange();
            replaceContent(channelId, message, inviteLabel(keyChanged, pending.safetyNum));
            if (keyChanged) {
                toast(
                    "⚠️ E2EE: your friend wants to start a secure channel, but their identity key has " +
                    "CHANGED since you last talked. This could be a new install — or an attacker. " +
                    "Click the ⚠️ button to see the safety number and compare it with them first.",
                    "critical"
                );
            } else {
                toast(
                    "🔐 Peer wants to start a secure channel. Click the lock " +
                    "to accept (or ignore to decline)."
                );
            }
            await markProcessedIfReal(message.id);
            return;
        }

        if (content.startsWith(PREFIX_ACK)) {
            if (fromSelf) {
                replaceContent(channelId, message, "🔐 [E2EE handshake response sent]");
                await markProcessedIfReal(message.id);
                return;
            }
            if (alreadyProcessed) {
                replaceContent(channelId, message, "🔐 [E2EE handshake response — historic]");
                return;
            }
            const s = sessions.get(channelId);
            if (!s || s.phase !== "init-sent" || !s.pendingEph) {
                log.warn("Got ACK with no pending init for channel", channelId);
                replaceContent(channelId, message, "🔐 [unexpected E2EE ACK]");
                await markProcessedIfReal(message.id);
                return;
            }
            const newSession = await handleAck(identity, s.pendingEph, content);

            // TOFU pin check. A changed key means whoever just answered is NOT
            // who answered last time. The keys are derived either way, but the
            // session is held: the new key is not pinned, the priming message
            // is not sent and `sendEncrypted` refuses, until the user has seen
            // the safety number and confirmed it (see `onLockClicked`). A toast
            // alone would be gone in seconds and leave a green lock behind.
            newSession.untrustedKey = !!newSession.peerIdPub
                && checkPeerKey(message.author.id, newSession.peerIdPub) === "changed";
            sessions.set(channelId, newSession);
            await persistState();
            notifyStateChange();

            if (newSession.untrustedKey) {
                replaceContent(
                    channelId, message,
                    "⚠️ [E2EE invitation answered with a DIFFERENT identity key than last time. " +
                    `Nothing will be sent until you click the ⚠️ button and confirm. Safety number: ${newSession.safetyNum}]`
                );
                toast(
                    "⚠️ E2EE: your friend's identity key has CHANGED since you last talked. " +
                    "Nothing will be sent until you click the ⚠️ button and confirm it.",
                    "critical"
                );
                await markProcessedIfReal(message.id);
                return;
            }

            if (newSession.peerIdPub) await pinPeerKey(message.author.id, newSession.peerIdPub);
            await sendPrime(channelId, newSession).catch(e => log.error("Failed to send priming message", e));

            replaceContent(channelId, message, "🔐 E2EE secure channel established.");
            if (settings.store.showSafetyNumberOnReady) {
                toast(
                    `🔐 Secure channel established. Safety #: ${newSession.safetyNum}`,
                    "success"
                );
            }
            await markProcessedIfReal(message.id);
            return;
        }

        if (content.startsWith(PREFIX_RESET)) {
            // Critical: dedupe + ignore-self for RESET. The old code would
            // happily wipe an active session if it ever re-saw our OWN past
            // RESET during a history load.
            if (fromSelf) {
                replaceContent(channelId, message, "🔐 [E2EE reset sent]");
                await markProcessedIfReal(message.id);
                return;
            }
            if (alreadyProcessed) {
                replaceContent(channelId, message, "🔐 [E2EE reset — historic]");
                return;
            }
            // The session is gone either way. What must NOT happen is the DM
            // quietly going back to plaintext: a RESET proves nothing about who
            // sent it, so anyone able to put a message into this DM could
            // otherwise switch encryption off for us, and the next thing typed
            // would go out in the clear. Nor should the next message silently
            // fire a new invitation at a peer who just said no. So the channel
            // stays enabled and closed until the user picks one of the two.
            if (enabledChannels.has(channelId)) {
                sessions.set(channelId, { ...emptySession(), phase: "peer-reset" });
                replaceContent(
                    channelId, message,
                    "⚠️ Your friend ended the encrypted chat. Nothing can be sent here until you click the ⚠️ button and choose what to do."
                );
                toast("⚠️ E2EE: your friend ended the encrypted chat. Click the ⚠️ button to choose what happens next.", "critical");
            } else {
                // We never opted in here, so this only withdraws an invitation.
                sessions.delete(channelId);
                replaceContent(channelId, message, "🔐 [E2EE invitation withdrawn]");
            }
            await persistState();
            notifyStateChange();
            await markProcessedIfReal(message.id);
            return;
        }

        if (content.startsWith(PREFIX_MSG)) {
            // Already decrypted before? (e.g. message was re-loaded)
            if (decryptedCache.has(message.id)) {
                replaceContent(channelId, message, decryptedCache.get(message.id)!);
                return;
            }

            // Our own outgoing ciphertext: we can't decrypt it (forward secrecy
            // moves the ratchet forward), but we don't need to — we stashed the
            // plaintext at send time. Copy it into the persistent cache now
            // that we know the message ID. Falls back to a placeholder for
            // messages sent before this client session (or from another device).
            //
            // The stash entry stays put: Discord re-announces the same send
            // (optimistic echo → gateway echo → MESSAGE_SUCCESS), and every one
            // of those has to resolve here. Only the real echo may write the
            // cache — an optimistic ID is client-side and would just be dead
            // weight in persisted storage.
            if (fromSelf) {
                const pt = recallOwnPlaintext(content);
                if (pt !== undefined) {
                    if (!optimistic) cacheDecrypted(message.id, pt);
                    replaceContent(channelId, message, pt);
                } else {
                    replaceContent(channelId, message, "🔐 [encrypted — sent]");
                }
                return;
            }

            const s = sessions.get(channelId);
            if (!s || s.phase !== "ready") {
                replaceContent(channelId, message, "🔐 [no session — cannot decrypt]");
                return;
            }
            // Saving is left to `enqueueIncoming`, which does it once per batch
            // instead of once per message.
            const plaintext = await decryptForSession(s, content);
            cacheDecrypted(message.id, plaintext);
            replaceContent(channelId, message, plaintext);
        }
    } catch (e) {
        log.error("Failed to handle incoming E2EE message", e);
        // Mark broken handshake messages processed so history loads don't
        // retry (and re-fail) them forever.
        if (isHandshake) await markProcessedIfReal(message.id).catch(() => { });
        replaceContent(
            channelId, message,
            isHandshake ? "🔐 [invalid E2EE handshake message]" : "🔐 [decryption failed]"
        );
    }
}

/** Make the renderer show our text instead of the raw cipher.
 *
 *  Mutating the Flux payload alone is NOT enough: MessageStore converts the
 *  payload into an immutable MessageRecord synchronously during dispatch, and
 *  this code runs async — after the store already took its copy. So we also
 *  go through the MessageUpdater API, which merges new fields into the cached
 *  record and forces a re-render. The payload mutation is kept as a cheap
 *  belt-and-suspenders for any consumer that reads the raw payload later. */
function replaceContent(channelId: string, message: any, newContent: string) {
    message.content = newContent;
    if ("contentParsed" in message) delete message.contentParsed;
    if ("embeds" in message && Array.isArray(message.embeds)) message.embeds = [];
    if (message.id) updateMessage(channelId, message.id, { content: newContent });
}

/** Send a raw text message bypassing our pre-send listener. The content
 *  starts with an E2EE prefix, which `isE2EEMessage` already short-circuits
 *  on, so onSend won't try to (re-)encrypt it.
 *
 *  Goes through Vencord's sendMessage util rather than MessageActions
 *  directly: the util supplies the `waitForChannelReady` / `options`
 *  arguments Discord's sendMessage requires — calling it without them makes
 *  the send reject silently and the message never goes out. */
function sendRaw(channelId: string, content: string) {
    Promise.resolve(sendMessage(channelId, { content }))
        .then((res: any) => {
            if (res?.ok === false) {
                log.error("sendRaw: send failed", res);
                toast("🔐 Failed to send E2EE message — check your connection.", "critical");
            }
        })
        .catch((e: any) => {
            log.error("sendRaw: send rejected", e);
            toast("🔐 Failed to send E2EE message — see console for details.", "critical");
        });
}

function isDM(ch: any): boolean {
    // Discord channel types: 1 = DM, 3 = group DM. We support 1 only.
    return ch?.type === 1;
}

function inviteLabel(keyChanged: boolean, safetyNum: string | null): string {
    return keyChanged
        ? "⚠️ [E2EE invitation — your friend's identity key has CHANGED since you last talked. " +
          `Compare this safety number with them before accepting: ${safetyNum ?? "click the ⚠️ button"}]`
        : "🔐 [E2EE handshake invitation — click the lock to accept]";
}

/** Oldest first. Snowflakes are decimal strings, so a shorter one is older. */
function bySnowflake(a: { id: string; }, b: { id: string; }): number {
    return a.id.length - b.id.length || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
}

/**
 * Process incoming messages in the channel's queue, in the order given.
 *
 * handleIncoming awaits crypto ops while mutating shared session state; if a
 * LOAD batch (or a LOAD racing a MESSAGE_CREATE, or a send) ran concurrently,
 * two ratchet steps could read the same chain key. The queue is shared with
 * `onSend` and the lock button for that reason.
 *
 * State is saved once at the end rather than after each message. A history
 * load can decrypt dozens of messages, and every save rewrites the whole
 * plaintext cache.
 */
function enqueueIncoming(channelId: string, messages: any[], optimistic = false) {
    // Almost every message Discord dispatches is not ours; don't queue those.
    const ours = messages.filter(m => typeof m?.content === "string" && isE2EEMessage(m.content));
    if (ours.length === 0) return;

    runExclusive(channelId, async () => {
        for (const message of ours) {
            await handleIncoming(channelId, message, optimistic)
                .catch(err => log.error("Failed to handle incoming message", err));
        }
        if (unsavedIncoming) {
            unsavedIncoming = false;
            await persistState().catch(err => {
                unsavedIncoming = true;
                throw err;
            });
        }
    }).catch(err => log.error("Failed to save E2EE state", err));
}

/** After an unlock: decrypt what arrived (and was rendered as a placeholder)
 *  while the vault was locked. */
function replayLockedMessages() {
    const byChannel = new Map<string, any[]>();
    for (const { channelId, message } of lockedMessages.values()) {
        if (!byChannel.has(channelId)) byChannel.set(channelId, []);
        byChannel.get(channelId)!.push(message);
    }
    lockedMessages.clear();

    for (const [channelId, messages] of byChannel) {
        enqueueIncoming(channelId, messages.sort(bySnowflake));
    }
}

// ------------------------------ FluxDispatcher subscriptions ------------------------------

const fluxHandlers: Array<[string, (e: any) => void]> = [];

function subscribe<T>(name: string, fn: (e: T) => void) {
    FluxDispatcher.subscribe(name as any, fn as any);
    fluxHandlers.push([name, fn as any]);
}

// ------------------------------ Lock toggle button ------------------------------

/** Padlock icon shown for this plugin in the chat-button settings UI. */
const LockIcon: IconComponent = ({ height = 20, width = 20, className }) => (
    <svg width={width} height={height} viewBox="0 0 24 24" className={className}>
        <path
            fill="currentColor"
            d="M12 1a5 5 0 0 0-5 5v3H6a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2h-1V6a5 5 0 0 0-5-5Zm-3 8V6a3 3 0 1 1 6 0v3H9Z"
        />
    </svg>
);

const LockButton: ChatBarButtonFactory = ({ channel, isMainChat }) => {
    // Subscribe to E2EE state changes so the icon/tooltip update the moment
    // the user toggles the lock or a handshake advances, without needing a
    // channel switch to force a re-render. Hooks come before the early returns:
    // the same button instance can be re-rendered for a different channel, and
    // a hook count that depends on the channel type crashes the component.
    const [, setTick] = React.useState(0);
    React.useEffect(() => {
        const fn = () => setTick(t => t + 1);
        stateSubscribers.add(fn);
        return () => { stateSubscribers.delete(fn); };
    }, []);
    const pendingUploads = useStateFromStores(
        [UploadAttachmentStore],
        () => channel ? UploadAttachmentStore.getUploads(channel.id, DraftType.ChannelMessage).length : 0
    );

    if (!isMainChat) return null; // skip forwarding modal etc.
    if (!channel || !isDM(channel)) return null;

    const sess = sessions.get(channel.id);
    const enabled = enabledChannels.has(channel.id);
    const safety = sess?.safetyNum ? ` — safety #: ${sess.safetyNum}` : "";

    let icon = "🔓";
    let tooltip = "E2EE off — click to enable";
    if (vaultLocked) {
        // Takes priority over everything: while locked we have no session state
        // to report, and unlocking is the only action available.
        icon = "🔑";
        tooltip = "Locked — click and enter your password";
    } else if (enabled && sess?.phase === "peer-reset") {
        icon = "⚠️";
        tooltip = "Your friend ended the encrypted chat — click to choose what happens next";
    } else if (sess && (sess.untrustedKey || (sess.phase === "init-recvd" && hasChangedKey(channel.id, sess)))) {
        icon = "⚠️";
        tooltip = "Your friend's identity key has changed — click to review it";
    } else if (enabled && sess?.phase === "ready") {
        icon = "🔒";
        tooltip = `E2EE active${safety}`;
    } else if (enabled && sess?.phase === "init-sent") {
        icon = "🟡";
        tooltip = "E2EE handshake in progress";
    } else if (sess?.phase === "init-recvd") {
        // Surfaced regardless of `enabled` so a user who hasn't yet opted in
        // can still see (and choose whether to accept) an inbound invitation.
        icon = "📩";
        tooltip = (enabled
            ? "Peer requested E2EE — send a message to accept"
            : "Peer requested E2EE — click the lock to accept") + safety;
    } else if (enabled) {
        icon = "🟡";
        tooltip = "E2EE enabled — send a message to start handshake";
    }

    // A file is waiting in the message box of an encrypted DM. Say so before
    // it is sent; the toast in `onSend` only comes once it is on its way.
    const fileWarning = enabled && pendingUploads > 0;
    if (fileWarning) tooltip = "Attached files are NOT encrypted — only your text is";

    return (
        <ChatBarButton tooltip={tooltip} onClick={() => { onLockClicked(channel.id).catch(e => log.error("Lock click failed", e)); }}>
            <span style={{ fontSize: "1.1em", position: "relative" }}>
                {icon}
                {fileWarning && (
                    <span
                        style={{
                            position: "absolute", top: "-7px", right: "-9px",
                            fontSize: "0.6em", lineHeight: 1, padding: "2px 3px", borderRadius: "8px",
                            background: "var(--status-danger, #da373c)",
                        }}
                    >
                        📎
                    </span>
                )}
            </span>
        </ChatBarButton>
    );
};

/** Lock next to the author's name on messages this plugin decrypted. */
const EncryptedBadge: MessageDecorationFactory = ({ message }) => {
    if (!message || !decryptedCache.has(message.id)) return null;
    return (
        <Tooltip text="End-to-end encrypted">
            {tooltipProps => (
                <span
                    {...tooltipProps}
                    style={{ display: "inline-flex", verticalAlign: "middle", marginLeft: "4px", color: "var(--text-positive, #23a55a)" }}
                >
                    <LockIcon width={14} height={14} />
                </span>
            )}
        </Tooltip>
    );
};

/** Notice under a message that arrived unencrypted in an E2EE-enabled DM. */
const UnencryptedNotice: MessageAccessoryFactory = ({ message }) => {
    if (!message || !unencryptedInSecureChat.has(message.id)) return null;
    return (
        <div
            style={{
                marginTop: "4px", padding: "4px 8px", width: "fit-content",
                fontSize: "12px", lineHeight: "16px", borderRadius: "4px",
                color: "var(--text-danger, #f23f43)",
                background: "color-mix(in srgb, var(--status-danger, #da373c) 12%, transparent)",
                borderLeft: "3px solid var(--status-danger, #da373c)",
            }}
        >
            ⚠️ Not encrypted — this message did not come through the secure channel.
        </div>
    );
};

/** Run a lock-button action in the channel's queue, and say so if it fails. */
function lockAction(channelId: string, action: () => Promise<void>) {
    runExclusive(channelId, action).catch(e => {
        log.error("Lock action failed", e);
        toast("🔐 That didn't work — see the console for details.", "critical");
    });
}

/**
 * The lock button.
 *
 * Three states change what leaves this computer or whom it is encrypted to,
 * and for those the click opens a dialog instead of acting: a live session
 * about to be turned off, a channel the peer reset, and a changed identity
 * key. The dialog is shown outside the channel queue so messages keep flowing
 * while it is open; the chosen action then runs inside the queue and looks at
 * the state again, since it may have moved on in the meantime.
 */
async function onLockClicked(channelId: string) {
    // While locked the button is an unlock affordance and nothing else —
    // toggling E2EE would operate on empty state and destroy real sessions.
    if (vaultLocked) {
        await unlockNow();
        return;
    }

    const s = sessions.get(channelId);
    const enabled = enabledChannels.has(channelId);

    if (enabled && s?.phase === "peer-reset") {
        const choice = await askChoice({
            title: "Your friend ended the encrypted chat",
            subtitle: "Nothing can be sent in this DM until you choose what happens next.",
            warning:
                "This notice can be faked by someone tampering with the chat. If you weren't expecting it, " +
                "check with your friend some other way before carrying on without encryption.",
            choices: [
                { id: "plain", text: "Continue without encryption", variant: "secondary" },
                { id: "encrypt", text: "Turn encryption back on", variant: "primary" },
            ],
        });
        if (choice === "encrypt") lockAction(channelId, async () => {
            if (sessions.get(channelId)?.phase !== "peer-reset") return;
            await startHandshake(channelId);
            toast("🔐 Invitation sent — the button shows 🔒 once your friend accepts.");
        });
        if (choice === "plain") lockAction(channelId, async () => {
            await turnOff(channelId);
            toast("🔐 E2EE disabled for this DM. Messages here are no longer encrypted.");
        });
        return;
    }

    if (s && (s.untrustedKey || (s.phase === "init-recvd" && hasChangedKey(channelId, s)))) {
        const choice = await askChoice({
            title: "Your friend's identity key has changed",
            subtitle:
                "This happens when they reinstall the plugin or clear its data. " +
                "It is also exactly what someone impersonating them would look like.",
            warning:
                "Compare the safety number below with your friend over a voice call or in person. " +
                "Only continue if you both see the same digits.",
            body: <Paragraph style={{ fontFamily: "var(--font-code)", fontSize: "1.1em" }}>{s.safetyNum}</Paragraph>,
            choices: [
                { id: "off", text: s.phase === "ready" ? "Turn encryption off" : "Decline", variant: "secondary" },
                { id: "trust", text: "They match — trust this key", variant: "critical-primary" },
            ],
        });
        if (choice === "trust") lockAction(channelId, () => trustChangedKey(channelId));
        if (choice === "off") lockAction(channelId, async () => {
            await turnOff(channelId);
            toast("🔐 The new key was not trusted. E2EE is off for this DM.");
        });
        return;
    }

    if (enabled && s?.phase === "ready") {
        const choice = await askChoice({
            title: "Turn off encryption?",
            subtitle:
                "New messages in this DM will be readable by Discord again. Your friend is told, and their side " +
                "stays closed until they confirm. Messages you have already saved stay readable.",
            choices: [
                { id: "keep", text: "Keep encrypted", variant: "secondary" },
                { id: "off", text: "Turn off", variant: "critical-primary" },
            ],
        });
        if (choice === "off") lockAction(channelId, async () => {
            await turnOff(channelId);
            toast("🔐 E2EE disabled for this DM.");
        });
        return;
    }

    lockAction(channelId, () => toggleLock(channelId));
}

/** The clicks that need no dialog: turning E2EE on, accepting an invitation,
 *  and backing out of a handshake that has not produced a session yet. */
async function toggleLock(channelId: string) {
    const pending = sessions.get(channelId);

    if (enabledChannels.has(channelId)) {
        // These need a dialog first. If the channel got here while the click
        // was waiting its turn, do nothing; the next click asks.
        if (pending?.phase === "ready" || pending?.phase === "peer-reset") return;

        await turnOff(channelId);
        toast(
            pending?.phase === "init-recvd"
                ? "🔐 Handshake invitation declined."
                : "🔐 E2EE disabled for this DM."
        );
        return;
    }

    if (!identity) return;
    if (pending?.phase === "init-recvd" && hasChangedKey(channelId, pending)) return;

    enabledChannels.add(channelId);
    await persistEnabled();
    notifyStateChange();
    if (pending?.phase === "init-recvd") {
        // Accept the pending invitation right away — the click IS the
        // explicit user gesture that gates buildAck.
        const sess = await acceptInvite(channelId, pending);
        if (sess) {
            const safety = settings.store.showSafetyNumberOnReady
                ? ` Safety #: ${sess.safetyNum}.`
                : "";
            toast(`🔐 E2EE handshake accepted.${safety}`, "success");
        }
    } else if (!pending || pending.phase === "none") {
        // Start the handshake immediately instead of waiting for (and
        // eating) the user's first typed message.
        await startHandshake(channelId);
        toast("🔐 Invitation sent — the button shows 🔒 once your friend accepts.");
    }
}

/** The user compared the safety number and accepts the peer's new identity key. */
async function trustChangedKey(channelId: string) {
    const s = sessions.get(channelId);
    const peerId = getPeerUserId(channelId);
    if (!s?.peerIdPub || !peerId) return;

    if (s.phase === "init-recvd") {
        enabledChannels.add(channelId);
        await persistEnabled();
        notifyStateChange();
        if (await acceptInvite(channelId, s)) toast("🔐 Invitation accepted with the new key.", "success");
        return;
    }

    if (s.phase === "ready" && s.untrustedKey) {
        s.untrustedKey = false;
        await pinPeerKey(peerId, s.peerIdPub);
        await sendPrime(channelId, s);
        notifyStateChange();
        toast("🔐 New key trusted. Secure channel established.", "success");
    }
}

// ------------------------------ Settings ------------------------------

const settings = definePluginSettings({
    showSafetyNumberOnReady: {
        type: OptionType.BOOLEAN,
        description: "Show the safety number in a notice when a session becomes ready.",
        default: true,
    },
    encryptDataAtRest: {
        type: OptionType.COMPONENT,
        component: EncryptAtRestSetting,
    },
});

// ------------------------------ Plugin definition ------------------------------

export default definePlugin({
    name: "E2EE",
    description: "End-to-end encryption for DMs using a Signal-style Double Ratchet (X25519 + HKDF + AES-GCM). Protocol v2.",
    authors: [
        {
            name: "Tobi",
            id: 1496025810870472744n
        }
    ],
    dependencies: ["ChatInputButtonAPI", "MessageEventsAPI", "MessageUpdaterAPI", "MessageDecorationsAPI", "MessageAccessoriesAPI"],
    settings,

    // Registered/unregistered automatically by the PluginManager.
    renderMessageDecoration: EncryptedBadge,
    renderMessageAccessory: UnencryptedNotice,

    chatBarButton: {
        icon: LockIcon,
        render: LockButton,
    },

    async start() {
        await loadAll();

        // Outgoing.
        addMessagePreSendListener(onSend);

        // Edits would bypass encryption entirely — block them.
        addMessagePreEditListener(onEdit);

        // Incoming via Flux. All paths go through the per-channel queue so
        // ratchet operations on one session never interleave.
        //
        // MESSAGE_CREATE fires twice for our own sends: once with optimistic=true for the
        // local echo Discord paints immediately, then again when the gateway
        // sends the real message back. Both have to render as plaintext; only
        // the second one carries an ID worth remembering.
        const onCreate = (e: { channelId: string; message: any; optimistic?: boolean }) => {
            // Types 0 and 19 are ordinary messages and replies; call and pin
            // notices are Discord's own and have nothing to encrypt.
            const isChat = e.message?.type === 0 || e.message?.type === 19;
            if (isChat && enabledChannels.has(e.channelId) && !isE2EEMessage(e.message.content ?? "")) {
                unencryptedInSecureChat.add(e.message.id);
                trimOldest(unencryptedInSecureChat, MAX_UNENCRYPTED_FLAGS);
            }
            enqueueIncoming(e.channelId, [e.message], e.optimistic === true);
        };
        subscribe("MESSAGE_CREATE", onCreate);

        // The HTTP send resolved: the optimistic record is swapped for the
        // server's copy, which puts raw ciphertext back into the store if this
        // lands after the gateway MESSAGE_CREATE. Re-render from the stash.
        subscribe("MESSAGE_SUCCESS", (e: { channelId: string; messageId?: string; message?: any }) => {
            if (e.messageId) inFlightWire.delete(e.messageId);
            if (e.message?.id) inFlightWire.delete(e.message.id);
            if (e.message) enqueueIncoming(e.channelId ?? e.message.channel_id, [e.message]);
        });

        // The send failed. Discord keeps the message around with a retry
        // affordance that re-sends whatever content the record holds, so undo
        // our plaintext rewrite before the user can click it.
        //
        // The ID is recorded even when there is nothing to undo yet: the
        // rewrite of this message's optimistic echo may still be waiting in
        // the channel queue, and `handleIncoming` checks this set so that it
        // does not run after the fact.
        subscribe("MESSAGE_SEND_FAILED", (e: { channelId: string; messageId: string }) => {
            failedSends.add(e.messageId);
            trimOldest(failedSends, MAX_IN_FLIGHT);

            const wire = inFlightWire.get(e.messageId);
            if (!wire) return;
            inFlightWire.delete(e.messageId);
            updateMessage(e.channelId, e.messageId, { content: wire });
        });

        // Bulk loads (history scrollback / channel switch). Discord delivers
        // these newest-first; process oldest-first so the ratchet mostly
        // advances in order instead of leaning on skipped-key handling.
        const onLoad = (e: { channelId: string; messages: any[] }) => {
            enqueueIncoming(e.channelId, (e.messages ?? []).filter(m => m?.id).sort(bySnowflake));
        };
        subscribe("LOAD_MESSAGES_SUCCESS", onLoad);

        // Edits: re-decrypt if the cached ciphertext changed somehow (shouldn't).
        subscribe("MESSAGE_UPDATE", (e: { message: any }) => {
            if (!e.message?.channel_id) return;
            enqueueIncoming(e.message.channel_id, [e.message]);
        });

        log.info("E2EE plugin started");
    },

    stop() {
        removeMessagePreSendListener(onSend);
        removeMessagePreEditListener(onEdit);
        for (const [name, fn] of fluxHandlers) FluxDispatcher.unsubscribe(name as any, fn as any);
        fluxHandlers.length = 0;

        // Drop the derived vault key so disabling the plugin actually re-locks
        // the data instead of leaving it readable until Discord restarts. With
        // the key gone a protected vault counts as locked, which is what keeps
        // anything still in flight from saving its state unencrypted.
        vaultKey = null;
        vaultLocked = vaultActive;

        log.info("E2EE plugin stopped");
    },
});
