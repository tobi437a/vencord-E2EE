/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * compress.ts — DEFLATE wrappers used to shrink message plaintext before it is
 * encrypted (protocol v2).
 *
 * Compression happens INSIDE the AEAD: we compress the plaintext, then encrypt
 * the result. Doing it the other way round would be pointless (ciphertext is
 * incompressible) and doing it outside the AEAD would leave the compressed
 * bytes unauthenticated.
 *
 * Why "deflate-raw" rather than "deflate"/"gzip": raw DEFLATE has no zlib
 * header (2 bytes) and no gzip header/trailer (18 bytes). On chat-sized
 * messages those fixed overheads are a meaningful chunk of the win.
 *
 * Everything here is Discord-free and dependency-free, so it is covered
 * directly by tests/compress.test.ts.
 */

/** The only format we emit or accept. Encoded implicitly by the v2 frame flag. */
export const COMPRESSION_FORMAT = "deflate-raw";

/**
 * Feature probe, memoised.
 *
 * `CompressionStream` shipped before "deflate-raw" was added to it, so the
 * existence of the constructor is NOT sufficient — a runtime that knows the
 * class but not the format throws a TypeError at construction time. The only
 * reliable probe is to actually construct one. The throwaway streams are never
 * written to and are collected normally.
 */
let supported: boolean | null = null;
export function compressionAvailable(): boolean {
    if (supported !== null) return supported;
    try {
        if (typeof CompressionStream === "undefined" || typeof DecompressionStream === "undefined") {
            supported = false;
        } else {
            new CompressionStream(COMPRESSION_FORMAT);
            new DecompressionStream(COMPRESSION_FORMAT);
            supported = true;
        }
    } catch {
        supported = false;
    }
    return supported;
}

/** Test seam: forget the memoised probe result. */
export function resetCompressionProbe(): void {
    supported = null;
}

/**
 * Push `bytes` through a transform stream and collect every output byte.
 *
 * The naive approach — grab a writer, `await writer.write()`, `await
 * writer.close()`, then read — can deadlock: the transform's output queue
 * fills up while nothing is draining it, so the write never settles. It also
 * tends to strand a floating promise, which surfaces as an unhandled rejection
 * when the stream errors.
 *
 * Both problems disappear if the source is a stream rather than an imperative
 * writer. `ReadableStream` -> `pipeThrough` -> `Response` gives us:
 *   - one producer that enqueues everything and closes immediately, so there is
 *     no second promise to leak;
 *   - `Response.arrayBuffer()` pulling from the readable end continuously, so
 *     backpressure resolves itself and the pipeline cannot stall;
 *   - a single awaited promise that rejects on any error anywhere in the chain
 *     (bad deflate data included), so failures propagate to exactly one place.
 *
 * `arrayBuffer()` also concatenates chunks for us, which removes the
 * hand-rolled offset arithmetic that would otherwise be the likely source of
 * byte corruption on multi-chunk (>~64 KiB) payloads.
 */
async function pump(bytes: Uint8Array, transform: GenericTransformStream): Promise<Uint8Array> {
    const source = new ReadableStream<Uint8Array>({
        start(controller) {
            // Enqueue the view as-is. Passing `bytes.buffer` instead would be a
            // corruption bug for any Uint8Array that is a view into a larger
            // ArrayBuffer (which `.slice()`d ratchet payloads frequently are).
            controller.enqueue(bytes);
            controller.close();
        }
    });
    const piped = source.pipeThrough(transform as TransformStream<Uint8Array, Uint8Array>);
    return new Uint8Array(await new Response(piped).arrayBuffer());
}

/** Raw DEFLATE. Rejects if the platform lacks support. */
export async function deflateRaw(input: Uint8Array): Promise<Uint8Array> {
    return pump(input, new CompressionStream(COMPRESSION_FORMAT));
}

/** Raw INFLATE. Rejects on truncated or corrupt input. */
export async function inflateRaw(input: Uint8Array): Promise<Uint8Array> {
    return pump(input, new DecompressionStream(COMPRESSION_FORMAT));
}
