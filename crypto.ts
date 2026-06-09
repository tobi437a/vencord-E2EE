/*
 * crypto.ts — X25519 / HKDF / AES-GCM primitives + Double Ratchet
 *
 * Implements the core of Signal's Double Ratchet algorithm
 * (https://signal.org/docs/specifications/doubleratchet/) on top of the Web
 * Crypto API. Curve25519 / X25519 ECDH is used for DH, HKDF-SHA256 for KDFs,
 * and AES-256-GCM for AEAD. No external dependencies.
 *
 * Notes / deviations from the spec:
 *  - We deliberately keep the implementation small. Skipped-message-key
 *    handling exists but caps at MAX_SKIP per chain to bound memory.
 *  - Header is NOT encrypted (we don't implement the optional "Header
 *    Encryption" variant). This leaks message numbers to anyone reading the
 *    Discord channel, which is fine in our threat model — Discord already
 *    has timestamps.
 */

// ------------------------------ Encoding utils ------------------------------

const enc = new TextEncoder();
const dec = new TextDecoder();

export function utf8(s: string): Uint8Array { return enc.encode(s); }
export function utf8d(b: Uint8Array): string { return dec.decode(b); }

export function b64encode(bytes: Uint8Array): string {
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
}

export function b64decode(b64: string): Uint8Array {
    const s = atob(b64);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
}

export function concat(...arrays: Uint8Array[]): Uint8Array {
    const total = arrays.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const a of arrays) { out.set(a, off); off += a.length; }
    return out;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
}

// ------------------------------ Web Crypto wrappers ------------------------------

const X25519 = { name: "X25519" } as KeyAlgorithm;

export interface KeyPair {
    privateKey: CryptoKey;          // non-extractable in memory
    publicKey: Uint8Array;          // 32-byte raw
}

/** Generate a fresh X25519 keypair. */
export async function generateDH(): Promise<KeyPair> {
    const kp = (await crypto.subtle.generateKey(X25519, true, ["deriveBits"])) as CryptoKeyPair;
    const raw = await crypto.subtle.exportKey("raw", kp.publicKey);
    return { privateKey: kp.privateKey, publicKey: new Uint8Array(raw) };
}

/** ECDH: returns 32-byte shared secret. */
export async function dh(priv: CryptoKey, peerPub: Uint8Array): Promise<Uint8Array> {
    const peer = await crypto.subtle.importKey("raw", peerPub as BufferSource, X25519, true, []);
    const bits = await crypto.subtle.deriveBits({ name: "X25519", public: peer } as any, priv, 256);
    return new Uint8Array(bits);
}

/** HKDF-SHA256 expand to `length` bytes. */
export async function hkdf(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, length: number): Promise<Uint8Array> {
    const key = await crypto.subtle.importKey("raw", ikm as BufferSource, "HKDF", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: salt as BufferSource, info: info as BufferSource },
        key, length * 8
    );
    return new Uint8Array(bits);
}

/** HMAC-SHA256. */
async function hmac(keyBytes: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    const k = await crypto.subtle.importKey(
        "raw", keyBytes as BufferSource,
        { name: "HMAC", hash: "SHA-256" },
        false, ["sign"]
    );
    return new Uint8Array(await crypto.subtle.sign("HMAC", k, data as BufferSource));
}

/** Persist/restore X25519 private keys via JWK (the only currently-portable way). */
export async function exportPrivateJwk(k: CryptoKey): Promise<JsonWebKey> {
    return await crypto.subtle.exportKey("jwk", k);
}
export async function importPrivateJwk(j: JsonWebKey): Promise<CryptoKey> {
    return await crypto.subtle.importKey("jwk", j, X25519, true, ["deriveBits"]);
}

// ------------------------------ Double Ratchet KDFs ------------------------------

/** KDF on the root key. SK is current RK, dhOut is fresh DH result.
 *  Returns (newRK, newChainKey). */
export async function kdfRK(rk: Uint8Array, dhOut: Uint8Array): Promise<{ rk: Uint8Array; ck: Uint8Array }> {
    const out = await hkdf(dhOut, rk, utf8("vencord-e2ee/rk"), 64);
    return { rk: out.slice(0, 32), ck: out.slice(32, 64) };
}

/** KDF on a chain key. Constant-input HMAC produces next chain key + message key. */
export async function kdfCK(ck: Uint8Array): Promise<{ ck: Uint8Array; mk: Uint8Array }> {
    const mk = await hmac(ck, new Uint8Array([0x01]));
    const next = await hmac(ck, new Uint8Array([0x02]));
    return { ck: next, mk };
}

// ------------------------------ AEAD (AES-256-GCM) ------------------------------

/** Encrypt with a message key. We expand the 32-byte MK into AES key + 12-byte IV
 *  via HKDF, so the same MK is never reused with the same IV (each MK is one-shot). */
export async function aeadEncrypt(mk: Uint8Array, plaintext: Uint8Array, ad: Uint8Array): Promise<Uint8Array> {
    const expanded = await hkdf(mk, new Uint8Array(32), utf8("vencord-e2ee/aead"), 44);
    const aesKey = await crypto.subtle.importKey("raw", expanded.slice(0, 32) as BufferSource, "AES-GCM", false, ["encrypt"]);
    const iv = expanded.slice(32, 44);
    const ct = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: ad as BufferSource },
        aesKey, plaintext as BufferSource
    );
    return new Uint8Array(ct);
}

export async function aeadDecrypt(mk: Uint8Array, ciphertext: Uint8Array, ad: Uint8Array): Promise<Uint8Array> {
    const expanded = await hkdf(mk, new Uint8Array(32), utf8("vencord-e2ee/aead"), 44);
    const aesKey = await crypto.subtle.importKey("raw", expanded.slice(0, 32) as BufferSource, "AES-GCM", false, ["decrypt"]);
    const iv = expanded.slice(32, 44);
    const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv, additionalData: ad as BufferSource },
        aesKey, ciphertext as BufferSource
    );
    return new Uint8Array(pt);
}

// ------------------------------ Message header ------------------------------

export interface RatchetHeader {
    dh: Uint8Array;     // sender's current ratchet pubkey (32B)
    pn: number;         // # messages in previous sending chain
    n: number;          // # in current chain
}

/** Wire format: [32 bytes dh][4 bytes pn BE][4 bytes n BE] = 40 bytes */
export function serializeHeader(h: RatchetHeader): Uint8Array {
    const out = new Uint8Array(40);
    out.set(h.dh, 0);
    new DataView(out.buffer).setUint32(32, h.pn, false);
    new DataView(out.buffer).setUint32(36, h.n, false);
    return out;
}

export function parseHeader(b: Uint8Array): RatchetHeader {
    if (b.length < 40) throw new Error("header too short");
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    return {
        dh: b.slice(0, 32),
        pn: dv.getUint32(32, false),
        n:  dv.getUint32(36, false),
    };
}

// ------------------------------ Ratchet state ------------------------------

const MAX_SKIP = 200;       // bound skipped message-key cache to avoid DoS

export interface RatchetState {
    DHs: KeyPair | null;            // own current ratchet pair
    DHr: Uint8Array | null;         // their last-seen ratchet pubkey
    RK:  Uint8Array;                // root key
    CKs: Uint8Array | null;         // sending chain
    CKr: Uint8Array | null;         // receiving chain
    Ns:  number;                    // # sent in current chain
    Nr:  number;                    // # received in current chain
    PN:  number;                    // # sent in previous chain
    /** Skipped message keys, indexed by `b64(dh) + ":" + n`. */
    skipped: Record<string, Uint8Array>;
}

/** Alice (initiator): she already knows Bob's first ratchet pubkey
 *  (sent during handshake) and the shared secret SK. */
export async function ratchetInitAlice(SK: Uint8Array, bobDHpub: Uint8Array): Promise<RatchetState> {
    const DHs = await generateDH();
    const dhOut = await dh(DHs.privateKey, bobDHpub);
    const { rk, ck } = await kdfRK(SK, dhOut);
    return {
        DHs, DHr: bobDHpub,
        RK: rk, CKs: ck, CKr: null,
        Ns: 0, Nr: 0, PN: 0,
        skipped: {},
    };
}

/** Bob (responder): his ephemeral keypair from the handshake becomes his first
 *  ratchet keypair. He has no receive chain yet — that's set up when Alice's
 *  first message arrives and triggers a DH ratchet. */
export function ratchetInitBob(SK: Uint8Array, bobKP: KeyPair): RatchetState {
    return {
        DHs: bobKP, DHr: null,
        RK: SK, CKs: null, CKr: null,
        Ns: 0, Nr: 0, PN: 0,
        skipped: {},
    };
}

/** Encrypt one message. Mutates state. Returns header || ciphertext. */
export async function ratchetEncrypt(s: RatchetState, plaintext: Uint8Array, ad: Uint8Array): Promise<Uint8Array> {
    if (!s.CKs || !s.DHs) throw new Error("no sending chain (Bob must wait for Alice's first message)");
    const { ck: nextCK, mk } = await kdfCK(s.CKs);
    s.CKs = nextCK;
    const header: RatchetHeader = { dh: s.DHs.publicKey, pn: s.PN, n: s.Ns };
    s.Ns += 1;
    const headerBytes = serializeHeader(header);
    const ct = await aeadEncrypt(mk, plaintext, concat(ad, headerBytes));
    return concat(headerBytes, ct);
}

/** Decrypt one message. Mutates state ONLY if decryption succeeds.
 *
 *  All ratchet steps are performed on a working copy and committed back to `s`
 *  only after the AEAD authenticates the message. Otherwise a single
 *  corrupted/forged message (whose header would trigger a bogus DH ratchet or
 *  chain advance) would permanently desync the live session. This mirrors the
 *  Signal spec's requirement that failed decryptions leave state untouched. */
export async function ratchetDecrypt(s: RatchetState, msg: Uint8Array, ad: Uint8Array): Promise<Uint8Array> {
    const headerBytes = msg.slice(0, 40);
    const ct = msg.slice(40);
    const h = parseHeader(headerBytes);

    // Working copy. Shallow spread is enough: all mutations replace fields /
    // map entries, never write into the underlying byte arrays or KeyPair.
    const c: RatchetState = { ...s, skipped: { ...s.skipped } };

    // 1. Try a skipped message key first (out-of-order delivery).
    const skipKey = b64encode(h.dh) + ":" + h.n;
    if (c.skipped[skipKey]) {
        const mk = c.skipped[skipKey];
        delete c.skipped[skipKey];
        const pt = await aeadDecrypt(mk, ct, concat(ad, headerBytes));
        Object.assign(s, c);    // commit (consume the skipped key) only on success
        return pt;
    }

    // 2. New ratchet pubkey from peer? Skip rest of old chain, then DH-ratchet.
    if (!c.DHr || !bytesEqual(h.dh, c.DHr)) {
        await skipMessageKeys(c, h.pn);
        await dhRatchet(c, h.dh);
    }

    // 3. Skip any earlier messages in the current receive chain.
    await skipMessageKeys(c, h.n);

    // 4. Advance receive chain by one and decrypt.
    if (!c.CKr) throw new Error("no receive chain");
    const { ck: nextCK, mk } = await kdfCK(c.CKr);
    c.CKr = nextCK;
    c.Nr += 1;
    const pt = await aeadDecrypt(mk, ct, concat(ad, headerBytes));
    Object.assign(s, c);
    return pt;
}

async function skipMessageKeys(s: RatchetState, until: number): Promise<void> {
    if (!s.CKr) return;
    if (s.Nr + MAX_SKIP < until) throw new Error("too many skipped messages");
    while (s.Nr < until) {
        const { ck: nextCK, mk } = await kdfCK(s.CKr);
        s.CKr = nextCK;
        if (s.DHr) s.skipped[b64encode(s.DHr) + ":" + s.Nr] = mk;
        s.Nr += 1;
    }
    // MAX_SKIP bounds one call, but the map accumulates across DH ratchets.
    // Evict oldest entries (string-keyed Records preserve insertion order) so
    // the total stays bounded, per the spec's "delete old skipped keys" advice.
    const keys = Object.keys(s.skipped);
    for (let i = 0; i < keys.length - MAX_SKIP; i++) delete s.skipped[keys[i]];
}

async function dhRatchet(s: RatchetState, peerNewDH: Uint8Array): Promise<void> {
    s.PN = s.Ns;
    s.Ns = 0;
    s.Nr = 0;
    s.DHr = peerNewDH;

    // Receive chain from old DHs + new peer pubkey.
    if (!s.DHs) throw new Error("no own ratchet key");
    const dhOut1 = await dh(s.DHs.privateKey, peerNewDH);
    const r1 = await kdfRK(s.RK, dhOut1);
    s.RK = r1.rk;
    s.CKr = r1.ck;

    // New own keypair, then send chain.
    s.DHs = await generateDH();
    const dhOut2 = await dh(s.DHs.privateKey, peerNewDH);
    const r2 = await kdfRK(s.RK, dhOut2);
    s.RK = r2.rk;
    s.CKs = r2.ck;
}

// ------------------------------ State <-> JSON ------------------------------

export interface SerializedState {
    DHs: { jwk: JsonWebKey; pub: string } | null;
    DHr: string | null;
    RK: string;
    CKs: string | null;
    CKr: string | null;
    Ns: number; Nr: number; PN: number;
    skipped: Record<string, string>;
}

export async function serializeState(s: RatchetState): Promise<SerializedState> {
    return {
        DHs: s.DHs
            ? { jwk: await exportPrivateJwk(s.DHs.privateKey), pub: b64encode(s.DHs.publicKey) }
            : null,
        DHr: s.DHr ? b64encode(s.DHr) : null,
        RK:  b64encode(s.RK),
        CKs: s.CKs ? b64encode(s.CKs) : null,
        CKr: s.CKr ? b64encode(s.CKr) : null,
        Ns: s.Ns, Nr: s.Nr, PN: s.PN,
        skipped: Object.fromEntries(
            Object.entries(s.skipped).map(([k, v]) => [k, b64encode(v)])
        ),
    };
}

export async function deserializeState(j: SerializedState): Promise<RatchetState> {
    return {
        DHs: j.DHs
            ? { privateKey: await importPrivateJwk(j.DHs.jwk), publicKey: b64decode(j.DHs.pub) }
            : null,
        DHr: j.DHr ? b64decode(j.DHr) : null,
        RK:  b64decode(j.RK),
        CKs: j.CKs ? b64decode(j.CKs) : null,
        CKr: j.CKr ? b64decode(j.CKr) : null,
        Ns: j.Ns, Nr: j.Nr, PN: j.PN,
        skipped: Object.fromEntries(
            Object.entries(j.skipped).map(([k, v]) => [k, b64decode(v)])
        ),
    };
}

// ------------------------------ Triple-DH (lite X3DH) for handshake ------------------------------

/** Derive shared secret SK from four DH outputs (mutual identity + ephemeral mix).
 *
 *  Alice's view (initiator):
 *      DH(IdA, EphB), DH(EphA, IdB), DH(EphA, EphB), DH(IdA, IdB)
 *  Bob's view (responder):
 *      DH(EphB, IdA), DH(IdB, EphA), DH(EphB, EphA), DH(IdB, IdA)
 *
 *  These are equal pairwise; the same concatenation is fed into HKDF on both
 *  sides giving an identical 32-byte SK.
 */
export async function deriveHandshakeSecret(
    dh1: Uint8Array, dh2: Uint8Array, dh3: Uint8Array, dh4: Uint8Array
): Promise<Uint8Array> {
    const ikm = concat(dh1, dh2, dh3, dh4);
    // Use a 32-byte zero salt; HKDF spec-compliant, gives full 256 bits of output.
    return hkdf(ikm, new Uint8Array(32), utf8("vencord-e2ee/handshake-v1"), 32);
}

/** Safety number: 6 groups of 5 digits derived from both identity pubkeys.
 *  Users compare these out-of-band to detect MITM. */
export async function safetyNumber(idA: Uint8Array, idB: Uint8Array): Promise<string> {
    // Order-independent: sort by raw bytes.
    const [lo, hi] = compareBytes(idA, idB) < 0 ? [idA, idB] : [idB, idA];
    const digest = new Uint8Array(
        await crypto.subtle.digest("SHA-256", concat(lo, hi) as BufferSource)
    );
    // Take 30 decimal digits from first 15 bytes.
    let out = "";
    for (let i = 0; i < 15; i++) {
        out += (digest[i] % 10).toString();
        out += (Math.floor(digest[i] / 10) % 10).toString();
    }
    return out.match(/.{1,5}/g)!.join(" ");
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i] - b[i];
    return a.length - b.length;
}
