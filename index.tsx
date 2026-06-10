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

import definePlugin, { OptionType, IconComponent } from "@utils/types";
import { definePluginSettings } from "@api/Settings";
import { DataStore } from "@api/index";
import {
    addMessagePreEditListener,
    addMessagePreSendListener,
    MessageEditListener,
    MessageSendListener,
    removeMessagePreEditListener,
    removeMessagePreSendListener,
} from "@api/MessageEvents";
import { ChatBarButton, ChatBarButtonFactory } from "@api/ChatButtons";
import { updateMessage } from "@api/MessageUpdater";
import {
    showToast, Toasts,
    FluxDispatcher, ChannelStore, MessageStore, UserStore, React,
} from "@webpack/common";
import { sendMessage } from "@utils/discord";
import { Logger } from "@utils/Logger";

import { b64encode } from "./crypto";
import {
    Identity, Session, SerializedIdentity, SerializedSession,
    emptySession, newIdentity,
    serializeIdentity, deserializeIdentity,
    serializeSession, deserializeSession,
    isE2EEMessage, encryptForSession, decryptForSession,
    buildInit, parseInit, buildAck, handleAck,
    PREFIX_INIT, PREFIX_ACK, PREFIX_MSG, PREFIX_RESET,
} from "./session";

// ------------------------------ Logger ------------------------------

const log = new Logger("E2EE");

// ------------------------------ Persistent storage ------------------------------

const STORE_IDENTITY = "E2EE_identity_v1";
const STORE_SESSIONS = "E2EE_sessions_v1";       // Record<channelId, SerializedSession>
const STORE_DECRYPTED = "E2EE_decrypted_v1";     // Record<messageId, string>
const STORE_ENABLED  = "E2EE_enabled_v1";        // Record<channelId, boolean>
const STORE_PROCESSED = "E2EE_processed_v1";     // string[] of handshake message IDs
const STORE_KNOWN_KEYS = "E2EE_knownKeys_v1";    // Record<userId, b64 identity pubkey>

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
 * plaintext here and move it into `decryptedCache` (keyed by the real message
 * ID) when the server echoes our message back via MESSAGE_CREATE. Without
 * this, your own messages would render as an "[encrypted]" placeholder
 * forever. Not persisted: it only needs to survive the send → echo window.
 */
const pendingOwnPlaintext = new Map<string, string>();
const MAX_PENDING_OWN = 200;

/** Cap so the persisted plaintext cache can't grow without bound.
 *  Maps iterate in insertion order, so this evicts the oldest entries. */
const MAX_DECRYPTED_CACHE = 5000;
function cacheDecrypted(messageId: string, plaintext: string) {
    decryptedCache.set(messageId, plaintext);
    while (decryptedCache.size > MAX_DECRYPTED_CACHE) {
        const oldest = decryptedCache.keys().next().value;
        if (oldest === undefined) break;
        decryptedCache.delete(oldest);
    }
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

async function loadAll() {
    // Identity
    const idRaw = await DataStore.get<SerializedIdentity>(STORE_IDENTITY);
    if (idRaw) {
        identity = await deserializeIdentity(idRaw);
    } else {
        identity = await newIdentity();
        await DataStore.set(STORE_IDENTITY, await serializeIdentity(identity));
        log.info("Generated new identity keypair");
    }

    // Sessions
    const sessRaw = await DataStore.get<Record<string, SerializedSession>>(STORE_SESSIONS) ?? {};
    for (const [chId, s] of Object.entries(sessRaw)) {
        try { sessions.set(chId, await deserializeSession(s)); }
        catch (e) { log.warn("Bad stored session for", chId, e); }
    }

    // Decrypted message cache
    const decRaw = await DataStore.get<Record<string, string>>(STORE_DECRYPTED) ?? {};
    for (const [mId, pt] of Object.entries(decRaw)) decryptedCache.set(mId, pt);

    // Enabled channels
    const enRaw = await DataStore.get<Record<string, boolean>>(STORE_ENABLED) ?? {};
    for (const [chId, on] of Object.entries(enRaw)) if (on) enabledChannels.add(chId);

    // Processed handshake message IDs
    const procRaw = await DataStore.get<string[]>(STORE_PROCESSED) ?? [];
    for (const id of procRaw) processedHandshakeMsgs.add(id);

    // Pinned peer identity keys
    const keysRaw = await DataStore.get<Record<string, string>>(STORE_KNOWN_KEYS) ?? {};
    for (const [uId, k] of Object.entries(keysRaw)) knownPeerKeys.set(uId, k);
}

async function persistSessions() {
    const out: Record<string, SerializedSession> = {};
    for (const [k, v] of sessions) out[k] = await serializeSession(v);
    await DataStore.set(STORE_SESSIONS, out);
}

async function persistDecrypted() {
    const out: Record<string, string> = {};
    for (const [k, v] of decryptedCache) out[k] = v;
    await DataStore.set(STORE_DECRYPTED, out);
}

async function persistEnabled() {
    const out: Record<string, boolean> = {};
    for (const id of enabledChannels) out[id] = true;
    await DataStore.set(STORE_ENABLED, out);
}

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
    await persistSessions();
    notifyStateChange();
    sendRaw(channelId, wire);
}

/** Responder side: accept a pending invitation — derive the session, pin the
 *  peer's identity key, and send the ACK. Returns the ready session, or null
 *  on failure (failure toasts are shown here; success toasts by the caller). */
async function acceptInvite(channelId: string, s: Session): Promise<Session | null> {
    if (!identity) return null;
    if (!s.peerIdPub || !s.peerEphPub) {
        log.error("init-recvd phase missing peer keys", channelId);
        sessions.delete(channelId);
        await persistSessions();
        notifyStateChange();
        showToast("🔐 Handshake failed — invitation was corrupt.", Toasts.Type.FAILURE);
        return null;
    }
    try {
        const { wire, session: newSession } = await buildAck(identity, s.peerIdPub, s.peerEphPub);
        sessions.set(channelId, newSession);
        await persistSessions();
        const peerId = getPeerUserId(channelId);
        if (peerId) await pinPeerKey(peerId, s.peerIdPub);
        notifyStateChange();
        sendRaw(channelId, wire);
        return newSession;
    } catch (e) {
        log.error("Failed to build ACK", e);
        showToast("🔐 Handshake failed.", Toasts.Type.FAILURE);
        return null;
    }
}

// ------------------------------ Outgoing message hook ------------------------------

const onSend: MessageSendListener = async (channelId, msg) => {
    if (!identity) return;

    // Don't molest our own handshake markers, etc.
    if (isE2EEMessage(msg.content)) return;

    if (!enabledChannels.has(channelId)) return;

    const ch = ChannelStore.getChannel(channelId);
    if (!ch || !isDM(ch)) return;     // Only DMs are supported.

    const s = sessions.get(channelId) ?? emptySession();

    // No session yet? Kick off handshake. (Normally the lock click already did
    // this; this path remains for e.g. a peer RESET wiping the session while
    // the channel stayed enabled.) The typed message is discarded so the user
    // doesn't accidentally send plaintext.
    if (s.phase === "none") {
        await startHandshake(channelId);
        showToast("🔐 E2EE handshake sent. Your message wasn't sent — please retype it after the lock turns green.");
        return { cancel: true };
    }

    if (s.phase === "init-sent") {
        // Still waiting on the peer's ACK. Refuse to send plaintext.
        showToast("🔐 E2EE handshake still in progress. Wait for the lock to turn green.");
        return { cancel: true };
    }

    if (s.phase === "init-recvd") {
        // Pending invitation in an already-enabled channel (the INIT arrived
        // after the user turned the lock on, so the lock click couldn't accept
        // it). Sending a message is the explicit accept gesture here. The typed
        // message is discarded: as responder we can't encrypt until the peer's
        // first encrypted message primes our sending chain.
        const sess = await acceptInvite(channelId, s);
        if (sess) {
            const safety = settings.store.showSafetyNumberOnReady
                ? ` Safety #: ${sess.safetyNum}.`
                : "";
            showToast(
                `🔐 E2EE handshake accepted.${safety} ` +
                "Your message wasn't sent — please retype it after the lock turns green.",
                Toasts.Type.SUCCESS
            );
        }
        return { cancel: true };
    }

    // Phase === "ready" — encrypt.
    try {
        const plaintext = msg.content;
        const wire = await encryptForSession(s, plaintext);
        msg.content = wire;
        // Remember our own plaintext so the echoed message renders readably.
        pendingOwnPlaintext.set(wire, plaintext);
        while (pendingOwnPlaintext.size > MAX_PENDING_OWN) {
            const oldest = pendingOwnPlaintext.keys().next().value;
            if (oldest === undefined) break;
            pendingOwnPlaintext.delete(oldest);
        }
        await persistSessions();    // ratchet state advances on every send
    } catch (e) {
        log.error("Encrypt failed", e);
        // As the handshake responder we cannot send until the peer's first
        // encrypted message arrives and primes our sending chain (the peer's
        // client sends one automatically on ACK receipt).
        showToast(
            String(e).includes("no sending chain")
                ? "🔐 Waiting for the peer's first encrypted message — try again in a moment."
                : "🔐 Encryption failed; aborting send.",
            Toasts.Type.FAILURE
        );
        return { cancel: true };
    }
};

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

    showToast(
        "🔐 Edit blocked: edits are not encrypted and would leak plaintext. Send a new message instead.",
        Toasts.Type.FAILURE
    );
    return { cancel: true };
};

// ------------------------------ Incoming message hook ------------------------------

async function handleIncoming(channelId: string, message: any): Promise<void> {
    if (!identity || !message?.content) return;
    const content: string = message.content;
    if (!isE2EEMessage(content)) return;

    const ch = ChannelStore.getChannel(channelId);
    if (!ch || !isDM(ch)) return;

    // Don't try to "decrypt" our own outgoing handshake / ciphertext (we
    // produced it, and our session state for sending is already advanced).
    // If we can't tell who authored the message (MESSAGE_UPDATE payloads may
    // omit `author`), bail rather than risk feeding our OWN ciphertext into
    // the ratchet — its unknown header pubkey would trigger a bogus DH
    // ratchet and wreck the session.
    const me = UserStore.getCurrentUser();
    if (!me?.id || !message.author?.id) return;
    const fromSelf = message.author.id === me.id;

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
                await markProcessed(message.id);
                return;
            }
            if (alreadyProcessed) {
                // Old INIT loaded from history; we already acted on it (or
                // explicitly decided not to). Render but do NOT mutate state.
                replaceContent(channelId, message, "🔐 [E2EE handshake invitation — historic]");
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
            // accept a fresh handshake.
            if (current && current.phase !== "none") {
                const reason =
                    current.phase === "ready"     ? "secure channel already active" :
                    current.phase === "init-sent" ? "outgoing handshake in flight"  :
                    /* init-recvd */                "another invitation already pending";
                replaceContent(channelId, message, `🔐 [E2EE handshake invitation ignored — ${reason}]`);
                showToast(
                    `🔐 Peer sent a handshake invitation, but ${reason}. ` +
                    "Toggle the lock off and on to reset if you want to accept it."
                );
                await markProcessed(message.id);
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
            const pending: Session = {
                phase: "init-recvd",
                peerIdPub,
                peerEphPub,
                pendingEph: null,
                ratchet: null,
                safetyNum: null,
            };
            sessions.set(channelId, pending);
            await persistSessions();
            notifyStateChange();
            replaceContent(
                channelId, message,
                keyChanged
                    ? "⚠️ [E2EE handshake invitation — peer's identity key has CHANGED since you last talked! Verify the safety number out of band before accepting.]"
                    : "🔐 [E2EE handshake invitation — click the lock to accept]"
            );
            if (keyChanged) {
                showToast(
                    "⚠️ E2EE: peer wants to start a secure channel, but their identity key has " +
                    "CHANGED since you last talked. This could be a new install — or an attacker. " +
                    "Verify the safety number out of band before accepting!",
                    Toasts.Type.FAILURE
                );
            } else {
                showToast(
                    "🔐 Peer wants to start a secure channel. Click the lock " +
                    "to accept (or ignore to decline)."
                );
            }
            await markProcessed(message.id);
            return;
        }

        if (content.startsWith(PREFIX_ACK)) {
            if (fromSelf) {
                replaceContent(channelId, message, "🔐 [E2EE handshake response sent]");
                await markProcessed(message.id);
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
                await markProcessed(message.id);
                return;
            }
            const newSession = await handleAck(identity, s.pendingEph, content);
            sessions.set(channelId, newSession);

            // TOFU pin check. The session is established either way (the user
            // initiated this handshake), but a changed key means whoever just
            // answered is NOT who answered last time — warn loudly, then pin
            // the new key so the next change warns again.
            const ackKeyChanged = newSession.peerIdPub
                ? checkPeerKey(message.author.id, newSession.peerIdPub) === "changed"
                : false;
            if (newSession.peerIdPub) await pinPeerKey(message.author.id, newSession.peerIdPub);

            // Prime the responder's sending chain. By Double Ratchet design
            // the responder (Bob) has no sending chain until our first
            // encrypted message reaches him and triggers his DH ratchet — so
            // until we send something, ALL of his sends would fail. Send one
            // encrypted message automatically so both sides can talk
            // immediately. It decrypts to a visible "channel established"
            // note on his end.
            try {
                const primeText = "🔐 Secure channel established.";
                const primeWire = await encryptForSession(newSession, primeText);
                pendingOwnPlaintext.set(primeWire, primeText);
                sendRaw(channelId, primeWire);
            } catch (e) {
                log.error("Failed to send priming message", e);
            }

            await persistSessions();
            notifyStateChange();
            replaceContent(channelId, message, "🔐 E2EE secure channel established.");
            if (ackKeyChanged) {
                showToast(
                    "⚠️ E2EE: secure channel established, but the peer's identity key has " +
                    "CHANGED since you last talked. Verify the safety number " +
                    `(${newSession.safetyNum}) out of band before trusting this channel!`,
                    Toasts.Type.FAILURE
                );
            } else if (settings.store.showSafetyNumberOnReady) {
                showToast(
                    `🔐 Secure channel established. Safety #: ${newSession.safetyNum}`,
                    Toasts.Type.SUCCESS
                );
            }
            await markProcessed(message.id);
            return;
        }

        if (content.startsWith(PREFIX_RESET)) {
            // Critical: dedupe + ignore-self for RESET. The old code would
            // happily wipe an active session if it ever re-saw our OWN past
            // RESET during a history load.
            if (fromSelf) {
                replaceContent(channelId, message, "🔐 [E2EE reset sent]");
                await markProcessed(message.id);
                return;
            }
            if (alreadyProcessed) {
                replaceContent(channelId, message, "🔐 [E2EE reset — historic]");
                return;
            }
            sessions.delete(channelId);
            await persistSessions();
            notifyStateChange();
            replaceContent(channelId, message, "🔐 Peer reset the secure channel.");
            await markProcessed(message.id);
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
            // plaintext at send time. Promote it into the persistent cache now
            // that we know the message ID. Falls back to a placeholder for
            // messages sent before this client session (or from another device).
            if (fromSelf) {
                const pt = pendingOwnPlaintext.get(content);
                if (pt !== undefined) {
                    pendingOwnPlaintext.delete(content);
                    cacheDecrypted(message.id, pt);
                    await persistDecrypted();
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
            const plaintext = await decryptForSession(s, content);
            cacheDecrypted(message.id, plaintext);
            await persistDecrypted();
            await persistSessions();
            replaceContent(channelId, message, plaintext);
        }
    } catch (e) {
        log.error("Failed to handle incoming E2EE message", e);
        // Mark broken handshake messages processed so history loads don't
        // retry (and re-fail) them forever.
        if (isHandshake) await markProcessed(message.id).catch(() => { });
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
                showToast("🔐 Failed to send E2EE message — check your connection.", Toasts.Type.FAILURE);
            }
        })
        .catch((e: any) => {
            log.error("sendRaw: send rejected", e);
            showToast("🔐 Failed to send E2EE message — see console for details.", Toasts.Type.FAILURE);
        });
}

function isDM(ch: any): boolean {
    // Discord channel types: 1 = DM, 3 = group DM. We support 1 only.
    return ch?.type === 1;
}

/**
 * Serialize all incoming-message processing per channel. handleIncoming
 * awaits crypto ops while mutating shared session state; if a LOAD batch (or
 * a LOAD racing a MESSAGE_CREATE) ran concurrently, two decrypts could read
 * the same chain key and derive wrong message keys or clobber counters.
 */
const channelQueues = new Map<string, Promise<void>>();
function enqueueIncoming(channelId: string, message: any) {
    const prev = channelQueues.get(channelId) ?? Promise.resolve();
    const next = prev
        .then(() => handleIncoming(channelId, message))
        .catch(err => log.error("Failed to handle incoming message", err));
    channelQueues.set(channelId, next);
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
    if (!isMainChat) return null;            // skip forwarding modal etc.
    if (!channel || !isDM(channel)) return null;

    // Subscribe to E2EE state changes so the icon/tooltip update the moment
    // the user toggles the lock or a handshake advances, without needing a
    // channel switch to force a re-render.
    const [, setTick] = React.useState(0);
    React.useEffect(() => {
        const fn = () => setTick(t => t + 1);
        stateSubscribers.add(fn);
        return () => { stateSubscribers.delete(fn); };
    }, []);

    const sess = sessions.get(channel.id);
    const enabled = enabledChannels.has(channel.id);

    let icon = "🔓";
    let tooltip = "E2EE off — click to enable";
    if (enabled && sess?.phase === "ready") {
        icon = "🔒";
        tooltip = `E2EE active${sess.safetyNum ? ` — safety #: ${sess.safetyNum}` : ""}`;
    } else if (enabled && sess?.phase === "init-sent") {
        icon = "🟡";
        tooltip = "E2EE handshake in progress";
    } else if (sess?.phase === "init-recvd") {
        // Surfaced regardless of `enabled` so a user who hasn't yet opted in
        // can still see (and choose whether to accept) an inbound invitation.
        icon = "📩";
        tooltip = enabled
            ? "Peer requested E2EE — send a message to accept"
            : "Peer requested E2EE — click the lock to accept";
    } else if (enabled) {
        icon = "🟡";
        tooltip = "E2EE enabled — send a message to start handshake";
    }

    return (
        <ChatBarButton tooltip={tooltip} onClick={() => onLockClicked(channel.id)}>
            <span style={{ fontSize: "1.1em" }}>{icon}</span>
        </ChatBarButton>
    );
};

async function onLockClicked(channelId: string) {
    const pending = sessions.get(channelId);
    if (enabledChannels.has(channelId)) {
        // Turn off + reset session.
        enabledChannels.delete(channelId);
        const had = sessions.delete(channelId);
        await persistEnabled();
        await persistSessions();
        notifyStateChange();
        if (had) sendRaw(channelId, PREFIX_RESET);
        showToast(
            pending?.phase === "init-recvd"
                ? "🔐 Handshake invitation declined."
                : "🔐 E2EE disabled for this DM."
        );
    } else {
        if (!identity) return;
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
                showToast(`🔐 E2EE handshake accepted.${safety}`, Toasts.Type.SUCCESS);
            }
        } else if (!pending || pending.phase === "none") {
            // Start the handshake immediately instead of waiting for (and
            // eating) the user's first typed message.
            await startHandshake(channelId);
            showToast("🔐 E2EE handshake sent — the lock turns green when the peer accepts.");
        }
    }
}

// ------------------------------ Settings ------------------------------

const settings = definePluginSettings({
    showSafetyNumberOnReady: {
        type: OptionType.BOOLEAN,
        description: "Show the safety number in a notice when a session becomes ready.",
        default: true,
    },
});

// ------------------------------ Plugin definition ------------------------------

export default definePlugin({
    name: "E2EE",
    description: "End-to-end encryption for DMs using a Signal-style Double Ratchet (X25519 + HKDF + AES-GCM).",
    authors: [
        {
            name: "Tobi",
            id: 1496025810870472744n
        }
    ],
    dependencies: ["ChatInputButtonAPI", "MessageEventsAPI", "MessageUpdaterAPI"],
    settings,

    // Registered/unregistered automatically by the PluginManager.
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
        const onCreate = (e: { channelId: string; message: any }) => {
            enqueueIncoming(e.channelId, e.message);
        };
        subscribe("MESSAGE_CREATE", onCreate);

        // Bulk loads (history scrollback / channel switch). Discord delivers
        // these newest-first; process oldest-first so the ratchet mostly
        // advances in order instead of leaning on skipped-key handling.
        const onLoad = (e: { channelId: string; messages: any[] }) => {
            const msgs = [...(e.messages ?? [])].sort((a, b) =>
                a.id?.length !== b.id?.length
                    ? a.id?.length - b.id?.length        // snowflakes: shorter id == older
                    : a.id < b.id ? -1 : 1
            );
            for (const m of msgs) enqueueIncoming(e.channelId, m);
        };
        subscribe("LOAD_MESSAGES_SUCCESS", onLoad);

        // Edits: re-decrypt if the cached ciphertext changed somehow (shouldn't).
        subscribe("MESSAGE_UPDATE", (e: { message: any }) => {
            if (!e.message?.channel_id) return;
            enqueueIncoming(e.message.channel_id, e.message);
        });

        log.info("E2EE plugin started");
    },

    stop() {
        removeMessagePreSendListener(onSend);
        removeMessagePreEditListener(onEdit);
        for (const [name, fn] of fluxHandlers) FluxDispatcher.unsubscribe(name as any, fn as any);
        fluxHandlers.length = 0;
        log.info("E2EE plugin stopped");
    },
});
