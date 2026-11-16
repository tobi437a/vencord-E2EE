/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * Tests for vault.ts — at-rest encryption of the plugin's stored data.
 *
 * PBKDF2 at the production iteration count takes a few hundred milliseconds per
 * derivation, which would make this suite crawl. Tests therefore derive at
 * MIN_PBKDF2_ITERATIONS and assert the production default separately.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { b64decode } from "../crypto";
import {
    DEFAULT_PBKDF2_ITERATIONS, deriveVaultKey, isVaultBlob, isVaultMeta,
    KDF_PBKDF2_SHA256, makeVaultMeta, MIN_PBKDF2_ITERATIONS, newKdfParams,
    SALT_BYTES, unlockVault, vaultDecrypt, vaultEncrypt, VaultKdfParams,
    WrongPassphraseError,
} from "../vault";

const FAST = MIN_PBKDF2_ITERATIONS;

describe("KDF parameters", () => {
    it("defaults to OWASP's floor for PBKDF2-SHA256", () => {
        assert.equal(DEFAULT_PBKDF2_ITERATIONS, 600_000);
        assert.equal(newKdfParams().iterations, DEFAULT_PBKDF2_ITERATIONS);
        assert.equal(newKdfParams().algorithm, KDF_PBKDF2_SHA256);
    });

    it("generates a fresh random salt each time", () => {
        const a = newKdfParams(), b = newKdfParams();
        assert.equal(b64decode(a.salt).length, SALT_BYTES);
        assert.notEqual(a.salt, b.salt);
    });

    it("rejects an unknown algorithm", async () => {
        const bogus = { ...newKdfParams(), algorithm: "rot13" } as unknown as VaultKdfParams;
        await assert.rejects(deriveVaultKey("passphrase", bogus), /unsupported vault KDF/);
    });

    it("rejects a downgraded iteration count", async () => {
        // Stored parameters are attacker-writable if the profile directory is,
        // so a tampered descriptor must not be able to make the KDF trivial.
        for (const iterations of [1, 1000, MIN_PBKDF2_ITERATIONS - 1]) {
            await assert.rejects(
                deriveVaultKey("passphrase", { ...newKdfParams(), iterations }),
                /refusing to derive/,
                `iterations=${iterations}`
            );
        }
    });

    it("is deterministic for the same passphrase and salt", async () => {
        const params = newKdfParams(FAST);
        const key = await deriveVaultKey("correct horse battery staple", params);
        const blob = await vaultEncrypt(key, { hello: "world" });

        const again = await deriveVaultKey("correct horse battery staple", params);
        assert.deepEqual(await vaultDecrypt(again, blob), { hello: "world" });
    });

    it("produces different keys for different salts", async () => {
        const key = await deriveVaultKey("same passphrase", newKdfParams(FAST));
        const blob = await vaultEncrypt(key, "secret");
        const other = await deriveVaultKey("same passphrase", newKdfParams(FAST));
        await assert.rejects(vaultDecrypt(other, blob), WrongPassphraseError);
    });
});

describe("record encryption", () => {
    it("round-trips structured values", async () => {
        const key = await deriveVaultKey("passphrase", newKdfParams(FAST));

        const values: unknown[] = [
            { jwk: { kty: "OKP", crv: "X25519", d: "abc", x: "def" }, pub: "Zm9v" },
            { "1234567890": { phase: "ready", safetyNum: "12345 67890 12345 67890 12345 67890" } },
            [1, 2, 3],
            "plain string",
            null,
        ];
        for (const value of values) {
            assert.deepEqual(await vaultDecrypt(key, await vaultEncrypt(key, value)), value);
        }
    });

    it("uses a fresh IV for every record", async () => {
        // A repeated IV under a reused AES-GCM key is catastrophic, and this key
        // is re-used on every single message the plugin persists.
        const key = await deriveVaultKey("passphrase", newKdfParams(FAST));
        const ivs = new Set<string>();
        for (let i = 0; i < 50; i++) ivs.add((await vaultEncrypt(key, "same plaintext")).iv);
        assert.equal(ivs.size, 50);
    });

    it("produces different ciphertext for identical plaintext", async () => {
        const key = await deriveVaultKey("passphrase", newKdfParams(FAST));
        const a = await vaultEncrypt(key, "identical");
        const b = await vaultEncrypt(key, "identical");
        assert.notEqual(a.ct, b.ct);
    });

    it("reports a wrong key as WrongPassphraseError", async () => {
        const params = newKdfParams(FAST);
        const right = await deriveVaultKey("right passphrase", params);
        const wrong = await deriveVaultKey("wrong passphrase", params);

        await assert.rejects(vaultDecrypt(wrong, await vaultEncrypt(right, "data")), WrongPassphraseError);
    });

    it("fails closed on tampered ciphertext rather than returning garbage", async () => {
        const key = await deriveVaultKey("passphrase", newKdfParams(FAST));
        const blob = await vaultEncrypt(key, { sensitive: true });

        const bytes = b64decode(blob.ct);
        bytes[0] ^= 0x01;
        const tampered = { ...blob, ct: btoa(String.fromCharCode(...bytes)) };
        await assert.rejects(vaultDecrypt(key, tampered), WrongPassphraseError);
    });

    it("fails closed on a tampered IV", async () => {
        const key = await deriveVaultKey("passphrase", newKdfParams(FAST));
        const blob = await vaultEncrypt(key, { sensitive: true });

        const iv = b64decode(blob.iv);
        iv[0] ^= 0x01;
        await assert.rejects(
            vaultDecrypt(key, { ...blob, iv: btoa(String.fromCharCode(...iv)) }),
            WrongPassphraseError
        );
    });
});

describe("type guards", () => {
    it("recognises a real blob and rejects legacy plaintext records", async () => {
        const key = await deriveVaultKey("passphrase", newKdfParams(FAST));
        assert.ok(isVaultBlob(await vaultEncrypt(key, "x")));

        // These are the shapes the plugin's own pre-encryption stores have; a
        // false positive here would make readSecret try to decrypt them.
        for (const notBlob of [
            null, undefined, "string", 42, [],
            { jwk: {}, pub: "abc" }, // SerializedIdentity
            { "123": { phase: "ready" } }, // sessions map
            { iv: "abc", ct: "def" }, // missing marker
        ]) {
            assert.ok(!isVaultBlob(notBlob), JSON.stringify(notBlob));
        }
    });

    it("recognises vault metadata", async () => {
        const { meta } = await makeVaultMeta("passphrase", FAST);
        assert.ok(isVaultMeta(meta));

        for (const notMeta of [null, {}, { kdf: {} }, { check: {} }, "meta"]) {
            assert.ok(!isVaultMeta(notMeta), JSON.stringify(notMeta));
        }
    });
});

describe("unlock", () => {
    it("accepts the right passphrase and returns a usable key", async () => {
        const { meta, key } = await makeVaultMeta("open sesame please", FAST);
        const blob = await vaultEncrypt(key, { identity: "secret" });

        const unlocked = await unlockVault("open sesame please", meta);
        assert.deepEqual(await vaultDecrypt(unlocked, blob), { identity: "secret" });
    });

    it("rejects a wrong passphrase before any real data is touched", async () => {
        const { meta } = await makeVaultMeta("open sesame please", FAST);
        await assert.rejects(unlockVault("not the passphrase", meta), WrongPassphraseError);
    });

    it("rejects an empty passphrase against a real one", async () => {
        const { meta } = await makeVaultMeta("open sesame please", FAST);
        await assert.rejects(unlockVault("", meta), WrongPassphraseError);
    });

    it("is case and whitespace sensitive", async () => {
        const { meta } = await makeVaultMeta("Correct Passphrase", FAST);
        for (const wrong of ["correct passphrase", "Correct Passphrase ", " Correct Passphrase"]) {
            await assert.rejects(unlockVault(wrong, meta), WrongPassphraseError);
        }
    });

    it("handles unicode passphrases", async () => {
        const passphrase = "pässwörd-🔐-漢字-with-length";
        const { meta, key } = await makeVaultMeta(passphrase, FAST);
        const blob = await vaultEncrypt(key, "data");

        assert.deepEqual(await vaultDecrypt(await unlockVault(passphrase, meta), blob), "data");
    });
});
