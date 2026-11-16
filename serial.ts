/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * serial.ts — ordering primitives for code that awaits while holding state.
 *
 * Ratchet operations read a chain key, await WebCrypto, then write the next
 * chain key back. Two of them overlapping on one session is not a cosmetic
 * race: a decrypt that commits after an encrypt rolls the sending chain back,
 * and the next message is then sealed under a message key (and IV) that was
 * already used. Everything that touches a channel's session therefore runs
 * through `runExclusive`, and everything that saves state through a
 * `serialWriter`.
 *
 * Discord-free and dependency-free; covered by tests/serial.test.ts.
 */

const tails = new Map<string, Promise<unknown>>();

/**
 * Run `fn` once every task queued earlier under the same `key` has settled.
 * A task that throws rejects its own promise but does not hold up later ones.
 */
export function runExclusive<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const next = (tails.get(key) ?? Promise.resolve()).then(fn);
    tails.set(key, next.catch(() => { }));
    return next;
}

/**
 * Wrap a "save the current state" function so that saves run one at a time and
 * in the order they were asked for.
 *
 * `write` must read the state it saves when it is called, not earlier. Calls
 * made while a save is still waiting to start share that save, which is what
 * keeps a burst of updates from turning into a burst of full rewrites: the
 * shared save has not read anything yet, so it will include all of them.
 */
export function serialWriter(write: () => Promise<void>): () => Promise<void> {
    let tail: Promise<void> = Promise.resolve();
    let waiting: Promise<void> | null = null;

    return () => waiting ??= tail = tail.catch(() => { }).then(() => {
        waiting = null;
        return write();
    });
}
