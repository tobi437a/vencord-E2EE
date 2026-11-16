/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * Per-channel session lifecycle, handshake protocol, persistence.
 *
 * ============================ PROTOCOL v2 ============================
 *
 * Wire format (all messages prefixed with 🔐 so they're visually distinct):
 *
 *   🔐⟨E2EE-INIT v2⟩b64(idPub‖ephPub)
 *       Sent by initiator. Contains 32-byte identity pubkey + 32-byte ephemeral
 *       pubkey. The recipient's plugin stashes it as a pending invitation; the
 *       ACK is only sent after an explicit user accept (lock click).
 *
 *   🔐⟨E2EE-ACK v2⟩b64(idPub‖ephPub)
 *       Responder's reply. Same shape. After both sides see this exchange they
 *       can derive the same 32-byte SK and bootstrap a Double Ratchet session.
 *
 *   🔐⟨E2EE v2⟩b64(header‖ciphertext)
 *       Normal encrypted message. The AEAD plaintext is a *frame*, not bare
 *       UTF-8 — see "Message frames" below.
 *
 *   🔐⟨E2EE-RESET v2⟩
 *       Either side can send this to tear down the session (e.g. if decryption
 *       starts failing because state got out of sync). It carries no proof of
 *       who sent it, so the other side discards its session but does NOT go
 *       back to plaintext: the DM stays closed ("peer-reset") until that user
 *       chooses to re-encrypt or to carry on unencrypted.
 *
 * Changes from v1:
 *   - Message bodies are framed with a 1-byte codec flag and may be DEFLATE
 *     compressed (see `packFrame`).
 *   - The AEAD additional-data string and the handshake HKDF info string are
 *     version-scoped, so a v1 and a v2 client can never derive matching keys.
 *     Combined with the changed prefixes this makes the versions cleanly
 *     non-interoperable rather than subtly broken: a v1 peer's messages are
 *     recognised (`isLegacyE2EEMessage`) and reported, not mis-decrypted.
 *
 * Message frames
 * --------------
 * The bytes handed to the ratchet are:
 *
 *     [1 byte codec flag][payload]
 *
 *     0x00 FRAME_RAW      payload is UTF-8 plaintext
 *     0x01 FRAME_DEFLATE  payload is raw-DEFLATE of UTF-8 plaintext
 *
 * The flag lives inside the AEAD, so it is authenticated and a tampering
 * Discord cannot flip a message between codecs.
 *
 * Compression is opportunistic: we only emit FRAME_DEFLATE when the compressed
 * payload is genuinely smaller AND decompresses back to the exact input bytes.
 * Most Discord messages are short enough that DEFLATE expands them, so in
 * practice the common case stays FRAME_RAW at a cost of one byte.
 */

import { compressionAvailable, deflateRaw, inflateRaw } from "./compress";
import {
    b64decode, b64encode, bytesEqual, concat, deriveHandshakeSecret, deserializeState, dh,
    exportPrivateJwk, generateDH, importPrivateJwk, KeyPair, ratchetDecrypt, ratchetEncrypt,
    ratchetInitAlice, ratchetInitBob, RatchetState, safetyNumber, SerializedState,
    serializeState, utf8, utf8dStrict,
} from "./crypto";

// ------------------------------ Wire markers ------------------------------

export const PROTOCOL_VERSION = "v2";

export const PREFIX_INIT = "🔐⟨E2EE-INIT v2⟩";
export const PREFIX_ACK = "🔐⟨E2EE-ACK v2⟩";
export const PREFIX_MSG = "🔐⟨E2EE v2⟩";
export const PREFIX_RESET = "🔐⟨E2EE-RESET v2⟩";

/** v1 markers. We never emit these; they exist so that a peer who hasn't
 *  upgraded — or our own pre-upgrade history — is recognised and labelled
 *  rather than rendered as a wall of base64. */
export const LEGACY_PREFIXES = [
    "🔐⟨E2EE-INIT v1⟩",
    "🔐⟨E2EE-ACK v1⟩",
    "🔐⟨E2EE v1⟩",
    "🔐⟨E2EE-RESET v1⟩",
] as const;

/** True for markers this build produces. */
export function isCurrentE2EEMessage(content: string): boolean {
    return content.startsWith(PREFIX_INIT)
        || content.startsWith(PREFIX_ACK)
        || content.startsWith(PREFIX_MSG)
        || content.startsWith(PREFIX_RESET);
}

/** True for v1 markers only. */
export function isLegacyE2EEMessage(content: string): boolean {
    return LEGACY_PREFIXES.some(p => content.startsWith(p));
}

/** True for any protocol version. Callers that need to answer "is this one of
 *  ours, hands off" (the pre-send and pre-edit hooks) must use this, so a v1
 *  message left in history is never treated as user text. */
export function isE2EEMessage(content: string): boolean {
    return isCurrentE2EEMessage(content) || isLegacyE2EEMessage(content);
}

// ------------------------------ Message framing ------------------------------

export const FRAME_RAW = 0x00;
export const FRAME_DEFLATE = 0x01;

/**
 * Don't even attempt DEFLATE below this many bytes. Raw DEFLATE needs a few
 * bytes of block overhead plus enough repetition to build a useful Huffman
 * table, so short messages — the overwhelming majority of Discord traffic —
 * always come out larger. Skipping them avoids pointless CPU on the hot path;
 * the size comparison in `packFrame` is what actually enforces correctness.
 */
export const COMPRESS_MIN_BYTES = 64;

/**
 * Build the AEAD plaintext for `text`.
 *
 * Compression is attempted only when it can plausibly pay off, and is accepted
 * only when it (a) produces fewer bytes and (b) round-trips back to the exact
 * input. The round-trip check costs one inflate on an already-small buffer and
 * buys a hard guarantee: a compression-layer bug can never silently ship a
 * message the peer will decode into different text. It degrades to FRAME_RAW,
 * which always works.
 *
 * Any failure in the compression path — unsupported format, a throwing stream,
 * a mismatched round-trip — falls through to FRAME_RAW rather than propagating,
 * because an uncompressed message is always a valid message.
 */
export async function packFrame(text: string): Promise<Uint8Array> {
    const raw = utf8(text);

    if (raw.length >= COMPRESS_MIN_BYTES && compressionAvailable()) {
        try {
            const deflated = await deflateRaw(raw);
            // Both framings carry the same 1-byte flag, so comparing payload
            // lengths directly is the right test for "did this actually help".
            if (deflated.length < raw.length && bytesEqual(await inflateRaw(deflated), raw)) {
                return concat(Uint8Array.of(FRAME_DEFLATE), deflated);
            }
        } catch {
            // Fall through to FRAME_RAW.
        }
    }

    return concat(Uint8Array.of(FRAME_RAW), raw);
}

/** Inverse of `packFrame`. Throws on an unknown flag, corrupt DEFLATE data or
 *  invalid UTF-8 — all of which mean the message is genuinely undecodable. */
export async function unpackFrame(frame: Uint8Array): Promise<string> {
    if (frame.length < 1) throw new Error("empty message frame");

    const flag = frame[0];
    const payload = frame.subarray(1);

    switch (flag) {
        case FRAME_RAW:
            return utf8dStrict(payload);
        case FRAME_DEFLATE:
            if (!compressionAvailable()) {
                throw new Error("peer sent a compressed message but DecompressionStream is unavailable here");
            }
            return utf8dStrict(await inflateRaw(payload));
        default:
            throw new Error(`unknown message codec flag 0x${flag.toString(16).padStart(2, "0")}`);
    }
}

// ------------------------------ Size accounting ------------------------------

/** Discord's hard cap for a single message. Nitro raises this to 4000, but we
 *  budget for the floor: a message that overflows is rejected at send time, and
 *  guessing high would turn that into a failed send instead. */
export const DISCORD_MAX_MESSAGE_LENGTH = 2000;

const HEADER_BYTES = 40; // 32B ratchet pubkey + 4B pn + 4B n
const AEAD_TAG_BYTES = 16; // AES-GCM tag

/** Length of `btoa` output for `n` input bytes, padding included. */
export function base64Length(n: number): number {
    return Math.ceil(n / 3) * 4;
}

/**
 * Exact length of the wire string a frame of `frameBytes` will produce.
 *
 * Every term is deterministic — AES-GCM ciphertext is exactly plaintext + tag,
 * and base64 expansion is a pure function of length — so this is an equality,
 * not an estimate. tests/session.test.ts asserts it against real encryptions.
 *
 * Measured in UTF-16 code units (`String.length`) because that is both what
 * `String.length` reports and the more conservative of the two plausible
 * countings: the 🔐 in the prefix is a surrogate pair, so this over-counts the
 * prefix by one versus code points. Erring high is the safe direction.
 */
export function projectedWireLength(frameBytes: number): number {
    return PREFIX_MSG.length + base64Length(HEADER_BYTES + frameBytes + AEAD_TAG_BYTES);
}

/** Largest frame that still fits `limit`. Inverse of `projectedWireLength`. */
export function maxFrameBytes(limit: number = DISCORD_MAX_MESSAGE_LENGTH): number {
    const base64Budget = limit - PREFIX_MSG.length;
    const byteBudget = Math.floor(base64Budget / 4) * 3;
    return byteBudget - HEADER_BYTES - AEAD_TAG_BYTES;
}

/** Thrown by `encryptForSession` when the finished message wouldn't fit.
 *  Raised *before* the ratchet advances — see `encryptForSession`. */
export class MessageTooLongError extends Error {
    readonly wireLength: number;
    readonly maxLength: number;

    constructor(wireLength: number, maxLength: number) {
        super(`encrypted message is ${wireLength} characters, over Discord's ${maxLength} limit`);
        this.name = "MessageTooLongError";
        this.wireLength = wireLength;
        this.maxLength = maxLength;
    }

    /** How many wire characters must go. */
    get overBy(): number {
        return this.wireLength - this.maxLength;
    }

    /** Roughly how many plaintext characters the user needs to cut.
     *
     *  Base64 turns 3 bytes into 4 characters, so shedding `overBy` wire
     *  characters needs about 3/4 as many bytes. This is a lower bound for
     *  compressed frames (where a byte of plaintext is worth less than a byte
     *  of frame) and exact for ASCII in a raw frame, so it is advisory only —
     *  the authoritative check is re-running the send. */
    get approxCharsToRemove(): number {
        return Math.ceil(this.overBy * 3 / 4);
    }
}

// ------------------------------ Identity ------------------------------

export interface Identity {
    privateKey: CryptoKey; // long-term X25519
    publicKey: Uint8Array; // 32 bytes
}

export interface SerializedIdentity {
    jwk: JsonWebKey;
    pub: string;
}

export async function serializeIdentity(id: Identity): Promise<SerializedIdentity> {
    return { jwk: await exportPrivateJwk(id.privateKey), pub: b64encode(id.publicKey) };
}

export async function deserializeIdentity(s: SerializedIdentity): Promise<Identity> {
    return { privateKey: await importPrivateJwk(s.jwk), publicKey: b64decode(s.pub) };
}

export async function newIdentity(): Promise<Identity> {
    const kp = await generateDH();
    return { privateKey: kp.privateKey, publicKey: kp.publicKey };
}

// ------------------------------ Per-channel session ------------------------------

/** Phases:
 *   - "none":        no E2EE
 *   - "init-sent":   Alice has sent INIT, awaiting ACK. Has pending ephemeral key.
 *   - "init-recvd":  Bob has received an INIT but has NOT yet replied. The
 *                    peer's identity + ephemeral pubkeys are stashed. The
 *                    session moves to "ready" only after the user explicitly
 *                    accepts (clicks the lock and sends a message), at which
 *                    point an ACK is constructed and the ratchet is set up.
 *                    This prevents auto-ACK in response to spammed INITs.
 *   - "ready":       Double Ratchet up, can send/recv encrypted messages.
 *   - "peer-reset":  The peer tore the session down. RESET is unauthenticated,
 *                    so it must not be able to switch a DM back to plaintext
 *                    by itself: this phase holds the channel closed (nothing
 *                    can be sent) until the user picks what happens next.
 */
export type SessionPhase = "none" | "init-sent" | "init-recvd" | "ready" | "peer-reset";

export interface Session {
    phase: SessionPhase;
    /** Peer's identity pubkey, learned during handshake. May be null until ACK arrives. */
    peerIdPub: Uint8Array | null;
    /** Peer's ephemeral pubkey, stashed only during "init-recvd" while awaiting
     *  the user's decision to accept. Consumed when we build the ACK. */
    peerEphPub: Uint8Array | null;
    /** Pending ephemeral keypair held only during "init-sent". */
    pendingEph: KeyPair | null;
    /** Live ratchet state, present iff phase === "ready". */
    ratchet: RatchetState | null;
    /** Safety number for `peerIdPub`. Set as soon as that key is known, so it
     *  can be compared before an invitation is accepted, not only after. */
    safetyNum: string | null;
    /** The peer's identity key differs from the one pinned for them and the
     *  user has not confirmed the new one yet. Nothing is sent meanwhile. */
    untrustedKey: boolean;
}

export interface SerializedSession {
    phase: SessionPhase;
    peerIdPub: string | null;
    peerEphPub: string | null;
    pendingEph: { jwk: JsonWebKey; pub: string } | null;
    ratchet: SerializedState | null;
    safetyNum: string | null;
    /** Absent in records written before this field existed. */
    untrustedKey?: boolean;
}

export async function serializeSession(s: Session): Promise<SerializedSession> {
    // Same rule as `serializeState`: take the whole snapshot before yielding.
    // `serializeState` reads its fields synchronously when called, so starting
    // it here (and awaiting it below) is what keeps the two halves consistent.
    const { pendingEph } = s;
    const ratchet = s.ratchet ? serializeState(s.ratchet) : null;
    const rest = {
        phase: s.phase,
        peerIdPub: s.peerIdPub ? b64encode(s.peerIdPub) : null,
        peerEphPub: s.peerEphPub ? b64encode(s.peerEphPub) : null,
        safetyNum: s.safetyNum,
        untrustedKey: s.untrustedKey,
    };
    return {
        ...rest,
        pendingEph: pendingEph
            ? { jwk: await exportPrivateJwk(pendingEph.privateKey), pub: b64encode(pendingEph.publicKey) }
            : null,
        ratchet: await ratchet,
    };
}

export async function deserializeSession(j: SerializedSession): Promise<Session> {
    return {
        phase: j.phase,
        peerIdPub: j.peerIdPub ? b64decode(j.peerIdPub) : null,
        peerEphPub: j.peerEphPub ? b64decode(j.peerEphPub) : null,
        pendingEph: j.pendingEph
            ? { privateKey: await importPrivateJwk(j.pendingEph.jwk), publicKey: b64decode(j.pendingEph.pub) }
            : null,
        ratchet: j.ratchet ? await deserializeState(j.ratchet) : null,
        safetyNum: j.safetyNum,
        untrustedKey: j.untrustedKey ?? false,
    };
}

export function emptySession(): Session {
    return {
        phase: "none",
        peerIdPub: null, peerEphPub: null,
        pendingEph: null, ratchet: null, safetyNum: null,
        untrustedKey: false,
    };
}

// ------------------------------ Handshake messages ------------------------------

function encodeHandshakeBody(idPub: Uint8Array, ephPub: Uint8Array): string {
    return b64encode(concat(idPub, ephPub));
}

function decodeHandshakeBody(payload: string): { idPub: Uint8Array; ephPub: Uint8Array } {
    const bytes = b64decode(payload);
    if (bytes.length !== 64) throw new Error(`bad handshake length: ${bytes.length}`);
    return { idPub: bytes.slice(0, 32), ephPub: bytes.slice(32, 64) };
}

/** Build the INIT marker text. Caller stores `pendingEph` in the session. */
export async function buildInit(id: Identity): Promise<{ wire: string; eph: KeyPair }> {
    const eph = await generateDH();
    const wire = PREFIX_INIT + encodeHandshakeBody(id.publicKey, eph.publicKey);
    return { wire, eph };
}

/** Parse an INIT message into its components. Side-effect-free — no key
 *  derivation, no state change, no automatic reply. Callers stash the result
 *  and wait for the user to explicitly accept before calling `buildAck`. */
export function parseInit(content: string): { peerIdPub: Uint8Array; peerEphPub: Uint8Array } {
    const payload = content.slice(PREFIX_INIT.length);
    const { idPub, ephPub } = decodeHandshakeBody(payload);
    return { peerIdPub: idPub, peerEphPub: ephPub };
}

/** Given a previously-parsed INIT (peer identity + ephemeral pubkeys), perform
 *  Bob's side of the handshake: generate our ephemeral, derive SK, init the
 *  ratchet, and produce the ACK wire to send back.
 *
 *  This used to be done automatically inside `handleInit` the moment an INIT
 *  was seen, which let a hostile peer trigger an outbound ACK by spamming
 *  fake INITs. Splitting it out forces the caller (index.tsx) to gate it
 *  behind an explicit user gesture. */
export async function buildAck(
    id: Identity, peerIdPub: Uint8Array, peerEphPub: Uint8Array
): Promise<{ wire: string; session: Session }> {
    const myEph = await generateDH();

    // Triple-DH (Bob's perspective):
    //   dh1 = DH(myEph, peerId)      [== Alice DH(IdA, EphB) on her side]
    //   dh2 = DH(myId,  peerEph)     [== Alice DH(EphA, IdB)]
    //   dh3 = DH(myEph, peerEph)
    //   dh4 = DH(myId,  peerId)
    const dh1 = await dh(myEph.privateKey, peerIdPub);
    const dh2 = await dh(id.privateKey, peerEphPub);
    const dh3 = await dh(myEph.privateKey, peerEphPub);
    const dh4 = await dh(id.privateKey, peerIdPub);

    // IMPORTANT: Both sides must mix the four DH outputs in the same order.
    // Match each of our outputs with the DH Alice computes over the same key
    // pair (DH is symmetric, so same pair == same output):
    //   our dh1 = DH(myEph, peerId)  — pair {IdA, EphB} — == Alice's dh1 = DH(myId,  peerEph)
    //   our dh2 = DH(myId,  peerEph) — pair {IdB, EphA} — == Alice's dh2 = DH(myEph, peerId)
    //   our dh3 = DH(myEph, peerEph) — pair {EphA, EphB} — == Alice's dh3
    //   our dh4 = DH(myId,  peerId)  — pair {IdA, IdB}  — == Alice's dh4
    // So both sides pass (dh1, dh2, dh3, dh4) as numbered on their own side.
    const SK = await deriveHandshakeSecret(dh1, dh2, dh3, dh4);

    const ratchet = ratchetInitBob(SK, myEph);
    const session: Session = {
        phase: "ready",
        peerIdPub,
        peerEphPub: null,
        pendingEph: null,
        ratchet,
        safetyNum: await safetyNumber(id.publicKey, peerIdPub),
        untrustedKey: false,
    };
    const wire = PREFIX_ACK + encodeHandshakeBody(id.publicKey, myEph.publicKey);
    return { wire, session };
}

/** Process an ACK as the original initiator. Requires the pending ephemeral
 *  keypair stored when we sent INIT. */
export async function handleAck(
    id: Identity, pendingEph: KeyPair, content: string
): Promise<Session> {
    const payload = content.slice(PREFIX_ACK.length);
    const { idPub: peerIdPub, ephPub: peerEphPub } = decodeHandshakeBody(payload);

    // Alice's perspective:
    //   dh1 = DH(myId,  peerEph)
    //   dh2 = DH(myEph, peerId)
    //   dh3 = DH(myEph, peerEph)
    //   dh4 = DH(myId,  peerId)
    const dh1 = await dh(id.privateKey, peerEphPub);
    const dh2 = await dh(pendingEph.privateKey, peerIdPub);
    const dh3 = await dh(pendingEph.privateKey, peerEphPub);
    const dh4 = await dh(id.privateKey, peerIdPub);
    const SK = await deriveHandshakeSecret(dh1, dh2, dh3, dh4);

    const ratchet = await ratchetInitAlice(SK, peerEphPub);
    return {
        phase: "ready",
        peerIdPub,
        peerEphPub: null,
        pendingEph: null,
        ratchet,
        safetyNum: await safetyNumber(id.publicKey, peerIdPub),
        untrustedKey: false,
    };
}

// ------------------------------ Encrypt / decrypt wrappers ------------------------------

/** Additional authenticated data bound into every message's AEAD. */
const AD = utf8("vencord-e2ee/v2");

/**
 * Encrypt one message.
 *
 * Ordering matters: the frame is built and size-checked BEFORE `ratchetEncrypt`
 * runs. `ratchetEncrypt` mutates the sending chain on every call, so a message
 * we end up refusing to send would otherwise burn a message key — leaving a
 * permanent gap that the peer can only paper over with skipped-key handling,
 * and that counts against MAX_SKIP. Rejecting first keeps a refused send
 * completely free of side effects on the session.
 *
 * @throws {MessageTooLongError} if the finished wire string exceeds Discord's cap.
 */
export async function encryptForSession(s: Session, plaintext: string): Promise<string> {
    if (s.phase !== "ready" || !s.ratchet) throw new Error("session not ready");

    const frame = await packFrame(plaintext);

    const projected = projectedWireLength(frame.length);
    if (projected > DISCORD_MAX_MESSAGE_LENGTH) {
        throw new MessageTooLongError(projected, DISCORD_MAX_MESSAGE_LENGTH);
    }

    const ct = await ratchetEncrypt(s.ratchet, frame, AD);
    return PREFIX_MSG + b64encode(ct);
}

/**
 * Decrypt one message.
 *
 * Note the asymmetry with `encryptForSession`: `ratchetDecrypt` commits the
 * ratchet as soon as the AEAD authenticates, so a frame that decrypts but fails
 * to *unpack* (unknown codec flag, corrupt DEFLATE, invalid UTF-8) still
 * consumes its message key. That is deliberate — the key genuinely was used,
 * and re-deriving it later would be worse than losing one undecodable message.
 */
export async function decryptForSession(s: Session, wire: string): Promise<string> {
    if (s.phase !== "ready" || !s.ratchet) throw new Error("session not ready");
    if (!wire.startsWith(PREFIX_MSG)) throw new Error("not an E2EE message");
    const frame = await ratchetDecrypt(s.ratchet, b64decode(wire.slice(PREFIX_MSG.length)), AD);
    return unpackFrame(frame);
}
