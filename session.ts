/*
 * Per-channel session lifecycle, handshake protocol, persistence.
 *
 * Wire format (all messages prefixed with 🔐 so they're visually distinct):
 *
 *   🔐⟨E2EE-INIT v1⟩b64(idPub‖ephPub)
 *       Sent by initiator. Contains 32-byte identity pubkey + 32-byte ephemeral
 *       pubkey. Recipient's plugin auto-replies if E2EE is enabled.
 *
 *   🔐⟨E2EE-ACK v1⟩b64(idPub‖ephPub)
 *       Responder's reply. Same shape. After both sides see this exchange they
 *       can derive the same 32-byte SK and bootstrap a Double Ratchet session.
 *
 *   🔐⟨E2EE v1⟩b64(header‖ciphertext)
 *       Normal encrypted message.
 *
 *   🔐⟨E2EE-RESET v1⟩
 *       Either side can send this to tear down the session (e.g. if decryption
 *       starts failing because state got out of sync). The other side will
 *       discard its session and the next encrypted send will trigger a new
 *       handshake.
 */

import {
    KeyPair, RatchetState, SerializedState,
    generateDH, dh, deriveHandshakeSecret,
    ratchetInitAlice, ratchetInitBob, ratchetEncrypt, ratchetDecrypt,
    serializeState, deserializeState,
    exportPrivateJwk, importPrivateJwk,
    b64encode, b64decode, utf8, utf8d, concat, safetyNumber,
} from "./crypto";

// ------------------------------ Wire markers ------------------------------

export const PREFIX_INIT  = "🔐⟨E2EE-INIT v1⟩";
export const PREFIX_ACK   = "🔐⟨E2EE-ACK v1⟩";
export const PREFIX_MSG   = "🔐⟨E2EE v1⟩";
export const PREFIX_RESET = "🔐⟨E2EE-RESET v1⟩";

export function isE2EEMessage(content: string): boolean {
    return content.startsWith(PREFIX_INIT)
        || content.startsWith(PREFIX_ACK)
        || content.startsWith(PREFIX_MSG)
        || content.startsWith(PREFIX_RESET);
}

// ------------------------------ Identity ------------------------------

export interface Identity {
    privateKey: CryptoKey;     // long-term X25519
    publicKey: Uint8Array;     // 32 bytes
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
 */
export type SessionPhase = "none" | "init-sent" | "init-recvd" | "ready";

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
    /** Cached safety number (computed on first transition to ready). */
    safetyNum: string | null;
}

export interface SerializedSession {
    phase: SessionPhase;
    peerIdPub: string | null;
    peerEphPub: string | null;
    pendingEph: { jwk: JsonWebKey; pub: string } | null;
    ratchet: SerializedState | null;
    safetyNum: string | null;
}

export async function serializeSession(s: Session): Promise<SerializedSession> {
    return {
        phase: s.phase,
        peerIdPub: s.peerIdPub ? b64encode(s.peerIdPub) : null,
        peerEphPub: s.peerEphPub ? b64encode(s.peerEphPub) : null,
        pendingEph: s.pendingEph
            ? { jwk: await exportPrivateJwk(s.pendingEph.privateKey), pub: b64encode(s.pendingEph.publicKey) }
            : null,
        ratchet: s.ratchet ? await serializeState(s.ratchet) : null,
        safetyNum: s.safetyNum,
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
    };
}

export function emptySession(): Session {
    return {
        phase: "none",
        peerIdPub: null, peerEphPub: null,
        pendingEph: null, ratchet: null, safetyNum: null,
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
    const dh1 = await dh(myEph.privateKey,    peerIdPub);
    const dh2 = await dh(id.privateKey,       peerEphPub);
    const dh3 = await dh(myEph.privateKey,    peerEphPub);
    const dh4 = await dh(id.privateKey,       peerIdPub);

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
    const dh1 = await dh(id.privateKey,        peerEphPub);
    const dh2 = await dh(pendingEph.privateKey, peerIdPub);
    const dh3 = await dh(pendingEph.privateKey, peerEphPub);
    const dh4 = await dh(id.privateKey,        peerIdPub);
    const SK  = await deriveHandshakeSecret(dh1, dh2, dh3, dh4);

    const ratchet = await ratchetInitAlice(SK, peerEphPub);
    return {
        phase: "ready",
        peerIdPub,
        peerEphPub: null,
        pendingEph: null,
        ratchet,
        safetyNum: await safetyNumber(id.publicKey, peerIdPub),
    };
}

// ------------------------------ Encrypt / decrypt wrappers ------------------------------

export async function encryptForSession(s: Session, plaintext: string): Promise<string> {
    if (s.phase !== "ready" || !s.ratchet) throw new Error("session not ready");
    const ad = utf8("vencord-e2ee/v1");
    const ct = await ratchetEncrypt(s.ratchet, utf8(plaintext), ad);
    return PREFIX_MSG + b64encode(ct);
}

export async function decryptForSession(s: Session, wire: string): Promise<string> {
    if (s.phase !== "ready" || !s.ratchet) throw new Error("session not ready");
    if (!wire.startsWith(PREFIX_MSG)) throw new Error("not an E2EE message");
    const ad = utf8("vencord-e2ee/v1");
    const pt = await ratchetDecrypt(s.ratchet, b64decode(wire.slice(PREFIX_MSG.length)), ad);
    return utf8d(pt);
}
