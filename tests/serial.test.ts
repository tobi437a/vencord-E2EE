/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * Tests for serial.ts — and for the race it exists to prevent: a send and a
 * receive overlapping on one ratchet session.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { b64decode, parseHeader } from "../crypto";
import { runExclusive, serialWriter } from "../serial";
import {
    buildAck, buildInit, decryptForSession, encryptForSession, handleAck,
    newIdentity, parseInit, PREFIX_MSG, Session,
} from "../session";

const tick = (ms = 1) => new Promise(resolve => setTimeout(resolve, ms));

/** Two ready sessions with both sending chains already in use. */
async function conversation(): Promise<{ alice: Session; bob: Session; }> {
    const idA = await newIdentity();
    const idB = await newIdentity();
    const { wire: init, eph } = await buildInit(idA);
    const { peerIdPub, peerEphPub } = parseInit(init);
    const { wire: ack, session: bob } = await buildAck(idB, peerIdPub, peerEphPub);
    const alice = await handleAck(idA, eph, ack);

    await decryptForSession(bob, await encryptForSession(alice, "prime"));
    await decryptForSession(alice, await encryptForSession(bob, "hello"));
    return { alice, bob };
}

const messageNumber = (wire: string) => parseHeader(b64decode(wire.slice(PREFIX_MSG.length))).n;

describe("runExclusive", () => {
    it("runs tasks for one key in the order they were queued", async () => {
        const order: string[] = [];
        await Promise.all([
            runExclusive("order", async () => { await tick(5); order.push("slow"); }),
            runExclusive("order", async () => { order.push("fast"); }),
        ]);
        assert.deepEqual(order, ["slow", "fast"]);
    });

    it("does not make different keys wait for each other", async () => {
        const order: string[] = [];
        await Promise.all([
            runExclusive("key-a", async () => { await tick(5); order.push("a"); }),
            runExclusive("key-b", async () => { order.push("b"); }),
        ]);
        assert.deepEqual(order, ["b", "a"]);
    });

    it("returns the task's result and keeps going after a failure", async () => {
        await assert.rejects(runExclusive("failure", async () => { throw new Error("boom"); }), /boom/);
        assert.equal(await runExclusive("failure", async () => 42), 42);
    });

    it("stops a receive from rolling back a concurrent send", async () => {
        const { alice, bob } = await conversation();
        const incoming = await encryptForSession(bob, "arrives while Alice is typing");

        const [, first] = await Promise.all([
            runExclusive("dm", () => decryptForSession(alice, incoming)),
            runExclusive("dm", () => encryptForSession(alice, "one")),
        ]);
        const second = await runExclusive("dm", () => encryptForSession(alice, "two"));

        // A reused message number is a reused AES-GCM key and IV.
        assert.notEqual(messageNumber(first), messageNumber(second));
        assert.equal(await decryptForSession(bob, first), "one");
        assert.equal(await decryptForSession(bob, second), "two");
    });

    it("documents the failure it prevents: unserialised, the same overlap reuses a message key", async () => {
        const { alice, bob } = await conversation();
        const incoming = await encryptForSession(bob, "arrives while Alice is typing");

        const [, first] = await Promise.all([
            decryptForSession(alice, incoming),
            encryptForSession(alice, "one"),
        ]);
        const second = await encryptForSession(alice, "two");

        assert.equal(messageNumber(first), messageNumber(second));
    });
});

describe("serialWriter", () => {
    it("never overlaps two writes", async () => {
        let active = 0;
        let peak = 0;
        const save = serialWriter(async () => {
            peak = Math.max(peak, ++active);
            await tick(20);
            active--;
        });

        const first = save();
        await tick();
        await Promise.all([first, save(), save()]);
        assert.equal(peak, 1);
    });

    it("saves the state as it is when the write starts, so the last write wins", async () => {
        let state = 0;
        const written: number[] = [];
        const save = serialWriter(async () => {
            const snapshot = state;
            await tick(20);
            written.push(snapshot);
        });

        state = 1;
        const first = save();
        await tick();
        state = 2;
        await Promise.all([first, save()]);

        assert.deepEqual(written, [1, 2]);
    });

    it("folds calls that arrive before a write has started into that write", async () => {
        let writes = 0;
        const save = serialWriter(async () => { writes++; await tick(20); });

        const running = save();
        await tick();
        const queued = [save(), save(), save()];
        await Promise.all([running, ...queued]);

        assert.equal(writes, 2);
    });

    it("recovers after a failed write", async () => {
        let fail = true;
        let writes = 0;
        const save = serialWriter(async () => {
            if (fail) throw new Error("disk full");
            writes++;
        });

        await assert.rejects(save(), /disk full/);
        fail = false;
        await save();
        assert.equal(writes, 1);
    });
});
