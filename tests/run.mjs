/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * Test runner: `node tests/run.mjs` from the plugin folder.
 *
 * Exists mainly to pin the invocation. Passing `tests/` directly to
 * `node --test` fails under tsx (its resolver tries to import the directory as
 * a module), so the glob has to be expanded here instead.
 *
 * The suites cover crypto.ts, compress.ts, session.ts and vault.ts — the
 * modules with no Vencord or Discord imports, which is why they can run in a
 * bare Node process at all. Node 22+ provides the same Web Crypto primitives
 * the browser does (X25519, HKDF, AES-GCM) plus DecompressionStream, so these
 * exercise the real implementations rather than mocks.
 */

import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const tests = readdirSync(here)
    .filter(f => f.endsWith(".test.ts"))
    .map(f => join(here, f));

if (tests.length === 0) {
    console.error("no test files found");
    process.exit(1);
}

const { status } = spawnSync(
    process.execPath,
    ["--import", "tsx", "--test", ...tests],
    { stdio: "inherit" }
);

process.exit(status ?? 1);
