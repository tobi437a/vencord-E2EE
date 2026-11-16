# Vencord E2EE

> End-to-end encryption for Discord DMs, implemented as a [Vencord](https://vencord.dev) userplugin.

Uses a **Signal-style Double Ratchet** under the hood: X25519 ECDH for key agreement, HKDF-SHA256 for key derivation, and AES-256-GCM for AEAD encryption. All cryptography runs through the browser's native **Web Crypto API** — no external JavaScript crypto libraries.

Discord only ever sees a blob of gibberish. Your messages are decrypted on your computer and your friend's, and nowhere else.

> 📖 Want the full technical breakdown — protocol, wire format, threat model, key handling? See **[IMPLEMENTATION.md](IMPLEMENTATION.md)**.

---

## Installation

> **Both people in the DM need to install this plugin.** There's no way around that — if only one of you has it, the other just sees gibberish.

1. Set up Vencord from source: <https://docs.vencord.dev/installing/custom-plugins/>
2. Drop this folder into `Vencord/src/userplugins/E2EE/`.
3. Run `pnpm build` and `pnpm inject`.
4. Open Discord, go to Vencord settings, and enable **E2EE**.
5. Restart Discord.

## Usage

1. Open a DM with a friend who also has the plugin installed.
2. Click the 🔓 button next to the message box. An invitation is sent and the button turns 🟡.
3. Your friend sees 📩. They click their lock button to accept.
4. Both of you now see 🔒, along with a **safety number** — a row of digits like `12345 67890 …`.
5. **Check the safety number matches before sending anything private.** Read it out over a voice call, or compare it in person. If both of you see the same digits, nobody is listening in. (Hover the 🔒 button any time to see it again.)
6. That's it. Everything you type from now on is encrypted.

To turn encryption off for a DM, click 🔒 again and confirm. Your friend's button turns ⚠️ and their side stays closed — nothing can be sent — until they choose to turn encryption back on or to carry on without it. Nobody drops back to unencrypted messages without choosing to.

### Lock button states

| Icon | Meaning |
|---|---|
| 🔓 | Encryption off — click to turn it on |
| 🟡 | Invitation sent, waiting for your friend to accept |
| 📩 | Your friend invited you — hover to see the safety number, click to accept |
| 🔒 | Encrypted — hover to see the safety number, click to turn off |
| ⚠️ | Needs your decision before anything can be sent — your friend ended the encrypted chat, or their identity key changed. Click to see the options |
| 🔑 | Your saved messages are locked — click and enter your password |

## Settings

**Show safety number when a chat becomes encrypted** *(on by default)*
Pops up the safety number as soon as a chat is set up, so you can check it straight away.

**Password-protect saved messages** *(off by default)*
The plugin keeps a copy of your encrypted messages on your computer so you can scroll back and still read them. Normally anyone with access to your computer could read that copy. Turn this on and it's locked behind a password that you enter once each time Discord starts.

> ⚠️ **There is no password reset.** If you forget it, every message you've sent or received with this plugin is gone permanently. Write it down somewhere safe.

Use a long password — a short one can be guessed by an attacker with your hard drive. A memorable phrase of several words is better than a short jumble of symbols.

## Good to know

**Your friend needs the plugin too**, and on the same version. If they see gibberish, they either don't have it installed or need to update.

**Only text is encrypted.** Images, files, voice messages, reactions, replies and embeds all go to Discord normally. Don't attach a photo and assume it's protected. While a file is attached in an encrypted DM the lock button shows a red 📎, and a warning pops up when you send it — the file still goes out, unencrypted.

**How to tell what was encrypted.** Messages the plugin decrypted have a small green lock after the sender's name. A message that arrives in an encrypted DM *without* being encrypted gets a red "Not encrypted" notice underneath it. That notice only covers messages arriving while Discord is open, not older history.

**Only one-on-one DMs.** Group DMs and server channels aren't supported.

**One computer per person.** Keys and saved messages live on the computer where you set the chat up. Your phone, the browser, or a second PC will only show gibberish for that DM, and anything you send from them is not encrypted.

**You can't edit encrypted messages.** Editing would send your new text unencrypted, so the plugin blocks it. Send a new message instead.

**Very long messages may be rejected.** Encryption makes text bigger, and Discord caps messages at 2000 characters. The plugin compresses your text first, which usually gives you plenty of room, but if a message is too long it will tell you roughly how much to cut rather than sending it broken.

**Discord still sees who you talk to and when.** Encryption hides *what* you said, not *that* you said it. Discord can still see who you message, how often, at what times, and roughly how long each message is.

**Client mods are technically against Discord's ToS.** Bans for using Vencord are rare in practice, but it's your account.

## If something goes wrong

**My friend just sees gibberish.** They don't have the plugin, or they're on an older version. Both of you need it installed and up to date.

**"Message too long."** Encryption adds overhead. Shorten it, or split it into two messages.

**A ⚠️ warning says my friend's identity key changed.** This happens if they reinstalled the plugin or cleared their data — but it's *also* what an attacker impersonating them would look like. Nothing is sent while the warning is up. Click the ⚠️ button: it shows the safety number for the new key. Compare it with your friend over voice or in person, and only then choose to trust it.

**The button turned ⚠️ and says my friend ended the encrypted chat.** They turned encryption off or declined your invitation. Click the button and pick: turn encryption back on (sends a new invitation), or continue without it. If you weren't expecting this, ask them another way first — the notice itself can be faked by someone tampering with the chat, which is exactly why the plugin won't go back to unencrypted messages on its own.

**Messages suddenly won't decrypt.** The two sides have got out of step. Click 🔒 and turn encryption off, then 🔓 to turn it back on and redo the setup. You'll keep the messages already saved on your computer.

**I forgot my password.** There's no way to recover it. You can clear the plugin's data in Vencord settings to start fresh, but the saved messages are gone.
