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

import definePlugin, { OptionType } from "@utils/types";
import { definePluginSettings } from "@api/Settings";
import { DataStore } from "@api/index";
import {
    addMessagePreSendListener,
    removeMessagePreSendListener,
    MessageSendListener,
} from "@api/MessageEvents";
import { addChatBarButton, removeChatBarButton, ChatBarButton } from "@api/ChatButtons";
import { showToast } from "@webpack/common";
import { FluxDispatcher, ChannelStore, UserStore, React } from "@webpack/common";
import { Logger } from "@utils/Logger";

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

let identity: Identity | null = null;
const sessions = new Map<string, Session>();
const decryptedCache = new Map<string, string>();
const enabledChannels = new Set<string>();
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

// ------------------------------ Outgoing message hook ------------------------------

const onSend: MessageSendListener = async (channelId, msg) => {
    if (!identity) return;

    // Don't molest our own handshake markers, etc.
    if (isE2EEMessage(msg.content)) return;

    if (!enabledChannels.has(channelId)) return;

    const ch = ChannelStore.getChannel(channelId);
    if (!ch || !isDM(ch)) return;     // Only DMs are supported.

    let s = sessions.get(channelId) ?? emptySession();

    // No session yet? Kick off handshake. The user's typed message is
    // discarded so they don't accidentally send plaintext — they'll be
    // re-prompted to send it once the handshake completes.
    if (s.phase === "none") {
        const { wire, eph } = await buildInit(identity);
        s = { ...emptySession(), phase: "init-sent", pendingEph: eph };
        sessions.set(channelId, s);
        await persistSessions();
        notifyStateChange();
        msg.content = wire;
        showToast(
            "🔐 E2EE handshake sent. Your message wasn't sent — please retype it after the lock turns green.",
            "OK", () => Notices.popNotice()
        );
        return;
    }

    if (s.phase === "init-sent") {
        // Still waiting on the peer's ACK. Refuse to send plaintext.
        msg.content = "";
        showToast(
            "🔐 E2EE handshake still in progress. Wait for the lock to turn green.",
            "OK", () => Notices.popNotice()
        );
        return;
    }

    if (s.phase === "init-recvd") {
        // Peer's INIT was stashed earlier; the user has now explicitly chosen
        // to accept it by enabling E2EE and sending a message. Build the ACK
        // here (NOT when the INIT arrived — auto-ACK was the spam vector). The
        // typed message is discarded for the same reason as in the INIT path:
        // it would otherwise be sent in plaintext alongside the handshake.
        if (!s.peerIdPub || !s.peerEphPub) {
            log.error("init-recvd phase missing peer keys", channelId);
            msg.content = "";
            sessions.delete(channelId);
            await persistSessions();
            notifyStateChange();
            return;
        }
        try {
            const { wire, session: newSession } = await buildAck(
                identity, s.peerIdPub, s.peerEphPub
            );
            sessions.set(channelId, newSession);
            await persistSessions();
            notifyStateChange();
            msg.content = wire;
            showToast(
                `🔐 E2EE handshake accepted. Safety #: ${newSession.safetyNum}. ` +
                "Your message wasn't sent — please retype it after the lock turns green.",
                "OK", () => Notices.popNotice()
            );
        } catch (e) {
            log.error("Failed to build ACK", e);
            showToast("🔐 Handshake failed; aborting send.", "OK", () => Notices.popNotice());
            msg.content = "";
        }
        return;
    }

    // Phase === "ready" — encrypt.
    try {
        const wire = await encryptForSession(s, msg.content);
        msg.content = wire;
        await persistSessions();    // ratchet state advances on every send
    } catch (e) {
        log.error("Encrypt failed", e);
        showToast("🔐 Encryption failed; aborting send.", "OK", () => Notices.popNotice());
        msg.content = "";
    }
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
    const me = UserStore.getCurrentUser();
    const fromSelf = message.author?.id === me?.id;

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
                replaceContent(message, "🔐 [E2EE handshake invitation sent]");
                await markProcessed(message.id);
                return;
            }
            if (alreadyProcessed) {
                // Old INIT loaded from history; we already acted on it (or
                // explicitly decided not to). Render but do NOT mutate state.
                replaceContent(message, "🔐 [E2EE handshake invitation — historic]");
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
                replaceContent(message, `🔐 [E2EE handshake invitation ignored — ${reason}]`);
                showToast(
                    `🔐 Peer sent a handshake invitation, but ${reason}. ` +
                    "Toggle the lock off and on to reset if you want to accept it.",
                    "OK", () => Notices.popNotice()
                );
                await markProcessed(message.id);
                return;
            }

            // Stash the INIT as a pending invitation. We do NOT auto-reply
            // here — that was the spam vector. The user must click the lock
            // and send a message, at which point onSend will run buildAck
            // and produce the actual ACK wire.
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
                message,
                "🔐 [E2EE handshake invitation — enable the lock and send a message to accept]"
            );
            showToast(
                "🔐 Peer wants to start a secure channel. Click the lock " +
                "and send a message to accept (or ignore to decline).",
                "OK", () => Notices.popNotice()
            );
            await markProcessed(message.id);
            return;
        }

        if (content.startsWith(PREFIX_ACK)) {
            if (fromSelf) {
                replaceContent(message, "🔐 [E2EE handshake response sent]");
                await markProcessed(message.id);
                return;
            }
            if (alreadyProcessed) {
                replaceContent(message, "🔐 [E2EE handshake response — historic]");
                return;
            }
            const s = sessions.get(channelId);
            if (!s || s.phase !== "init-sent" || !s.pendingEph) {
                log.warn("Got ACK with no pending init for channel", channelId);
                replaceContent(message, "🔐 [unexpected E2EE ACK]");
                await markProcessed(message.id);
                return;
            }
            const newSession = await handleAck(identity, s.pendingEph, content);
            sessions.set(channelId, newSession);
            await persistSessions();
            notifyStateChange();
            replaceContent(message, "🔐 E2EE secure channel established.");
            showToast(
                `🔐 Secure channel established. Safety #: ${newSession.safetyNum}`,
                "OK", () => Notices.popNotice()
            );
            await markProcessed(message.id);
            return;
        }

        if (content.startsWith(PREFIX_RESET)) {
            // Critical: dedupe + ignore-self for RESET. The old code would
            // happily wipe an active session if it ever re-saw our OWN past
            // RESET during a history load.
            if (fromSelf) {
                replaceContent(message, "🔐 [E2EE reset sent]");
                await markProcessed(message.id);
                return;
            }
            if (alreadyProcessed) {
                replaceContent(message, "🔐 [E2EE reset — historic]");
                return;
            }
            sessions.delete(channelId);
            await persistSessions();
            notifyStateChange();
            replaceContent(message, "🔐 Peer reset the secure channel.");
            await markProcessed(message.id);
            return;
        }

        if (content.startsWith(PREFIX_MSG)) {
            // Already decrypted before? (e.g. message was re-loaded)
            if (decryptedCache.has(message.id)) {
                replaceContent(message, decryptedCache.get(message.id)!);
                return;
            }

            // Our own outgoing ciphertext: we can't decrypt it (forward secrecy
            // moves the ratchet forward), but we don't need to — we already
            // saw the plaintext when we typed it. Show a placeholder.
            if (fromSelf) {
                replaceContent(message, "🔐 [encrypted — sent]");
                return;
            }

            const s = sessions.get(channelId);
            if (!s || s.phase !== "ready") {
                replaceContent(message, "🔐 [no session — cannot decrypt]");
                return;
            }
            const plaintext = await decryptForSession(s, content);
            decryptedCache.set(message.id, plaintext);
            await persistDecrypted();
            await persistSessions();
            replaceContent(message, plaintext);
        }
    } catch (e) {
        log.error("Failed to handle incoming E2EE message", e);
        replaceContent(message, "🔐 [decryption failed]");
    }
}

/** Mutate a Discord message object so the renderer shows our text instead of
 *  the raw cipher. We patch both .content and the parsed content array if the
 *  store has already parsed it. */
function replaceContent(message: any, newContent: string) {
    message.content = newContent;
    // Force re-parse: clear any pre-parsed structure so Discord re-runs its
    // markdown / mention parser on our new content.
    if ("contentParsed" in message) delete message.contentParsed;
    if ("embeds" in message && Array.isArray(message.embeds)) message.embeds = [];
}

/** Send a raw text message bypassing our pre-send listener. We do this by
 *  dispatching directly through Discord's MessageActions. */
async function sendRaw(channelId: string, content: string) {
    // Dynamic import to avoid Vencord's lazy-require complaining at load time.
    const MessageActions = (await import("@webpack/common")).MessageActions
        ?? (window as any).webpackChunkdiscord_app /* fallback */;
    if (!MessageActions?.sendMessage) {
        log.error("MessageActions.sendMessage unavailable; cannot auto-send ACK");
        return;
    }
    // We mark this content with a hidden flag the listener checks for so it
    // doesn't try to encrypt it. The marker is just the E2EE prefix itself,
    // which `isE2EEMessage` already short-circuits on.
    MessageActions.sendMessage(channelId, { content, invalidEmojis: [], tts: false, validNonShortcutEmojis: [] });
}

function isDM(ch: any): boolean {
    // Discord channel types: 1 = DM, 3 = group DM. We support 1 only.
    return ch?.type === 1;
}

// ------------------------------ FluxDispatcher subscriptions ------------------------------

const fluxHandlers: Array<[string, (e: any) => void]> = [];

function subscribe<T extends { type: string }>(name: string, fn: (e: T) => void) {
    FluxDispatcher.subscribe(name as any, fn as any);
    fluxHandlers.push([name, fn as any]);
}

// ------------------------------ Lock toggle button ------------------------------

const LockButton: ChatBarButton = ({ channel, isMainChat }) => {
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
            : "Peer requested E2EE — click the lock then send a message to accept";
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
        if (had) await sendRaw(channelId, PREFIX_RESET);
        showToast(
            pending?.phase === "init-recvd"
                ? "🔐 Handshake invitation declined."
                : "🔐 E2EE disabled for this DM.",
            "OK", () => Notices.popNotice()
        );
    } else {
        enabledChannels.add(channelId);
        await persistEnabled();
        notifyStateChange();
        const msg = pending?.phase === "init-recvd"
            ? "🔐 E2EE enabled. Send a message to accept the peer's handshake (your first message will not be delivered — retype it after the lock turns green)."
            : "🔐 E2EE enabled. Send a message to start the handshake (your first message will not be delivered — retype it after the lock turns green).";
        showToast(msg, "OK", () => Notices.popNotice());
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
    dependencies: ["ChatInputButtonAPI", "MessageEventsAPI"],
    settings,

    async start() {
        await loadAll();

        // Outgoing.
        addMessagePreSendListener(onSend);

        // Incoming via Flux.
        const onCreate = (e: { channelId: string; message: any }) => {
            handleIncoming(e.channelId, e.message).catch(err => log.error(err));
        };
        subscribe("MESSAGE_CREATE", onCreate);

        // Bulk loads (history scrollback / channel switch).
        const onLoad = (e: { channelId: string; messages: any[] }) => {
            for (const m of e.messages ?? []) {
                handleIncoming(e.channelId, m).catch(err => log.error(err));
            }
        };
        subscribe("LOAD_MESSAGES_SUCCESS", onLoad);

        // Edits: re-decrypt if the cached ciphertext changed somehow (shouldn't).
        subscribe("MESSAGE_UPDATE", (e: { message: any }) => {
            if (!e.message?.channel_id) return;
            handleIncoming(e.message.channel_id, e.message).catch(err => log.error(err));
        });

        // Lock button on the chat bar.
        addChatBarButton("E2EE", LockButton);

        log.info("E2EE plugin started");
    },

    stop() {
        removeMessagePreSendListener(onSend);
        for (const [name, fn] of fluxHandlers) FluxDispatcher.unsubscribe(name as any, fn as any);
        fluxHandlers.length = 0;
        removeChatBarButton("E2EE");
        log.info("E2EE plugin stopped");
    },
});