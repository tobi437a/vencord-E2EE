/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * PassphraseModal.tsx — prompts for the at-rest encryption passphrase.
 *
 * Two modes:
 *   "create"  first-time setup. Asks twice and enforces a length minimum,
 *             because PBKDF2 is not memory-hard (see vault.ts) and a short
 *             passphrase is the whole attack.
 *   "unlock"  startup. Single field, retries in place on a wrong passphrase so
 *             a typo doesn't leave the plugin locked for the session.
 */

import { Heading } from "@components/Heading";
import { Paragraph } from "@components/Paragraph";
import { RenderModalProps } from "@vencord/discord-types";
import { Modal, openModal, React, TextInput } from "@webpack/common";

/** Short passphrases are the practical break against a GPU-parallel KDF. */
export const MIN_PASSPHRASE_LENGTH = 12;

export type PassphraseMode = "create" | "unlock";

interface PassphraseModalProps {
    props: RenderModalProps;
    mode: PassphraseMode;
    /** Resolve to an error string to keep the modal open, or null on success. */
    verify(passphrase: string): Promise<string | null>;
    onDone(passphrase: string): void;
}

function PassphraseModal({ props, mode, verify, onDone }: PassphraseModalProps) {
    const [value, setValue] = React.useState("");
    const [confirm, setConfirm] = React.useState("");
    const [error, setError] = React.useState<string | null>(null);
    const [busy, setBusy] = React.useState(false);

    const creating = mode === "create";

    function localError(): string | null {
        if (value.length < MIN_PASSPHRASE_LENGTH) {
            return `Use at least ${MIN_PASSPHRASE_LENGTH} characters.`;
        }
        if (creating && value !== confirm) return "The two passwords don't match.";
        return null;
    }

    async function submit() {
        if (busy) return;

        // In unlock mode the only local rule is "not empty" — an existing
        // passphrase that predates a stricter minimum must still work.
        const local = creating ? localError() : (value.length === 0 ? "Enter your password." : null);
        if (local) { setError(local); return; }

        setBusy(true);
        setError(null);
        try {
            const err = await verify(value);
            if (err) {
                setError(err);
                setValue("");
                setConfirm("");
                return;
            }
            onDone(value);
        } catch (e) {
            setError(String(e));
        } finally {
            setBusy(false);
        }
    }

    const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
        if (e.key === "Enter") void submit();
    };

    return (
        <Modal
            {...props}
            size="sm"
            title={creating ? "Choose a password" : "Enter your password"}
            subtitle={
                creating
                    ? "This password protects the encrypted messages saved on this computer."
                    : "Unlock the encrypted messages saved on this computer."
            }
            notice={
                creating
                    ? {
                        type: "critical",
                        message: "Write it down somewhere safe. If you forget it, every message you've sent or received with this plugin is lost for good — there is no way to reset it."
                    }
                    : undefined
            }
            actions={[
                {
                    text: "Cancel",
                    variant: "secondary",
                    onClick: () => props.onClose(),
                    disabled: busy
                },
                {
                    text: creating ? "Set password" : "Unlock",
                    variant: "primary",
                    onClick: () => void submit(),
                    loading: busy,
                    disabled: busy
                }
            ]}
        >
            <div>
                <Heading tag="h5">Password</Heading>
                <TextInput
                    type="password"
                    autoFocus
                    value={value}
                    onChange={setValue}
                    onKeyDown={onKeyDown}
                    editable={!busy}
                    placeholder={creating ? `At least ${MIN_PASSPHRASE_LENGTH} characters` : ""}
                    style={{ marginBottom: creating ? "10px" : "4px" }}
                />

                {creating && (
                    <>
                        <Heading tag="h5">Type it again</Heading>
                        <TextInput
                            type="password"
                            value={confirm}
                            onChange={setConfirm}
                            onKeyDown={onKeyDown}
                            editable={!busy}
                            style={{ marginBottom: "4px" }}
                        />
                    </>
                )}

                {error && (
                    <Paragraph style={{ color: "var(--text-danger)", marginTop: "6px" }}>
                        {error}
                    </Paragraph>
                )}

                {busy && (
                    <Paragraph style={{ marginTop: "6px", opacity: 0.7 }}>
                        Checking… this takes a second on purpose, to make guessing slow.
                    </Paragraph>
                )}
            </div>
        </Modal>
    );
}

/**
 * Open the modal and wait for a decision.
 *
 * Resolves with the passphrase once `verify` accepts it, or with null if the
 * user dismisses the modal by any route (Cancel, Escape, clicking out). The
 * `settled` flag is what distinguishes "closed after success" from "closed
 * without answering" — `onCloseCallback` fires for both, and treating a
 * successful close as a cancel would silently drop the passphrase.
 */
export function askPassphrase(
    mode: PassphraseMode,
    verify: (passphrase: string) => Promise<string | null>
): Promise<string | null> {
    return new Promise(resolve => {
        let settled = false;
        openModal(
            props => (
                <PassphraseModal
                    props={props}
                    mode={mode}
                    verify={verify}
                    onDone={passphrase => {
                        settled = true;
                        resolve(passphrase);
                        props.onClose();
                    }}
                />
            ),
            { onCloseCallback: () => { if (!settled) resolve(null); } }
        );
    });
}
