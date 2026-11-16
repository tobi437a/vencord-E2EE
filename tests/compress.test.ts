/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * Tests for compress.ts.
 *
 * The point of these is byte fidelity and promise hygiene. A compression bug
 * that mangles one byte in a hundred messages would look, to the user, exactly
 * like a broken ratchet — so the round-trip cases deliberately cover awkward
 * shapes (empty, single byte, multi-chunk, buffer views, binary) rather than
 * just "a string works".
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { compressionAvailable, deflateRaw, inflateRaw } from "../compress";
import { bytesEqual, concat, utf8, utf8dStrict } from "../crypto";

describe("compression availability", () => {
    it("reports support on this platform", () => {
        assert.equal(compressionAvailable(), true, "Node 22+ should support deflate-raw");
    });

    it("is stable across repeated probes", () => {
        assert.equal(compressionAvailable(), compressionAvailable());
    });
});

describe("deflate/inflate round-trips", () => {
    const cases: Array<[string, Uint8Array]> = [
        ["empty", new Uint8Array(0)],
        ["one byte", Uint8Array.of(0)],
        ["all byte values", Uint8Array.from({ length: 256 }, (_, i) => i)],
        ["highly repetitive", utf8("a".repeat(10_000))],
        ["incompressible random", crypto.getRandomValues(new Uint8Array(4096))],
        ["natural language", utf8("the quick brown fox jumps over the lazy dog. ".repeat(40))],
        ["astral unicode", utf8("🔐🎉🚀 ünïcödé 漢字かな ".repeat(100))],
    ];

    for (const [name, input] of cases) {
        it(`round-trips ${name} (${input.length} bytes)`, async () => {
            const out = await inflateRaw(await deflateRaw(input));
            assert.equal(out.length, input.length, "length must match exactly");
            assert.ok(bytesEqual(out, input), "bytes must match exactly");
        });
    }

    it("round-trips a payload larger than one stream chunk", async () => {
        // Streams hand back multiple chunks past ~64 KiB; this is where any
        // hand-rolled chunk-joining would corrupt data.
        // getRandomValues caps at 64 KiB per call, so fill in slices.
        const big = new Uint8Array(512 * 1024);
        for (let off = 0; off < big.length; off += 65536) {
            crypto.getRandomValues(big.subarray(off, Math.min(off + 65536, big.length)));
        }
        assert.ok(bytesEqual(await inflateRaw(await deflateRaw(big)), big));
    });

    it("round-trips a view into a larger buffer without dragging in neighbours", async () => {
        // The frames handed to packFrame are frequently `.subarray()`/`.slice()`
        // views. Enqueuing `bytes.buffer` instead of the view would silently
        // compress the padding too.
        const backing = concat(utf8("XXXXXXXX"), utf8("payload of interest"), utf8("YYYYYYYY"));
        const view = backing.subarray(8, 8 + "payload of interest".length);
        const out = await inflateRaw(await deflateRaw(view));
        assert.equal(utf8dStrict(out), "payload of interest");
    });

    it("actually compresses repetitive input", async () => {
        const input = utf8("hello world ".repeat(500));
        assert.ok((await deflateRaw(input)).length < input.length / 10);
    });
});

describe("error handling", () => {
    it("rejects on corrupt deflate data rather than returning garbage", async () => {
        await assert.rejects(inflateRaw(crypto.getRandomValues(new Uint8Array(64))));
    });

    it("rejects on truncated deflate data", async () => {
        const full = await deflateRaw(utf8("some text that will definitely compress ".repeat(50)));
        await assert.rejects(inflateRaw(full.subarray(0, full.length - 3)));
    });

    it("surfaces failures as a rejection with no unhandled rejection left behind", async () => {
        // If the implementation stranded a floating writer promise, this would
        // print an UnhandledPromiseRejection warning and (under Node's default
        // policy) take the process down after the test resolved.
        const unhandled: unknown[] = [];
        const onUnhandled = (reason: unknown) => unhandled.push(reason);
        process.on("unhandledRejection", onUnhandled);
        try {
            for (let i = 0; i < 25; i++) {
                await assert.rejects(inflateRaw(crypto.getRandomValues(new Uint8Array(32))));
            }
            // Let any stranded rejection reach the handler.
            await new Promise(r => setTimeout(r, 50));
            assert.deepEqual(unhandled, []);
        } finally {
            process.off("unhandledRejection", onUnhandled);
        }
    });
});

describe("concurrency", () => {
    it("keeps parallel operations independent", async () => {
        // Each call must build its own stream; a shared one would interleave
        // bytes between messages.
        const inputs = Array.from({ length: 40 }, (_, i) => utf8(`message number ${i} `.repeat(20)));
        const outputs = await Promise.all(
            inputs.map(async input => inflateRaw(await deflateRaw(input)))
        );
        outputs.forEach((out, i) => {
            assert.ok(bytesEqual(out, inputs[i]), `mismatch at index ${i}`);
        });
    });
});
