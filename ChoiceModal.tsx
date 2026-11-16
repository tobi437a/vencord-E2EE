/*
 * Vencord, a Discord client mod
 * Copyright (c) 2026 Vendicated and contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * ChoiceModal.tsx — asks the user to pick one of a few actions.
 *
 * Used wherever a click would otherwise change what leaves this computer
 * without saying so: turning encryption off, carrying on after the peer turned
 * it off, and trusting a changed identity key.
 */

import { ModalActionVariant } from "@vencord/discord-types";
import { Modal, openModal } from "@webpack/common";
import { ReactNode } from "react";

export interface Choice<T extends string> {
    id: T;
    text: string;
    variant: ModalActionVariant;
}

export interface ChoiceOptions<T extends string> {
    title: string;
    subtitle?: ReactNode;
    /** Shown as a red notice between the subtitle and the body. */
    warning?: string;
    body?: ReactNode;
    choices: Choice<T>[];
}

/**
 * Open the modal and wait for a decision. Resolves with the chosen id, or with
 * null if the modal is dismissed any other way (Escape, clicking out), so
 * "no answer" can never be mistaken for one of the choices.
 */
export function askChoice<T extends string>({ title, subtitle, warning, body, choices }: ChoiceOptions<T>): Promise<T | null> {
    return new Promise(resolve => {
        let settled = false;
        openModal(
            props => (
                <Modal
                    {...props}
                    size="sm"
                    title={title}
                    subtitle={subtitle}
                    notice={warning ? { type: "critical", message: warning } : undefined}
                    actions={choices.map(({ id, text, variant }) => ({
                        text,
                        variant,
                        onClick: () => {
                            settled = true;
                            resolve(id);
                            props.onClose();
                        }
                    }))}
                >
                    {body}
                </Modal>
            ),
            { onCloseCallback: () => { if (!settled) resolve(null); } }
        );
    });
}
