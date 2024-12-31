# Lichess E2EE

Adds passphrase-based symmetric end-to-end encryption over Lichess chat (using AES-256 in CBC mode via CryptoJS)

## Validation
Text color:

* **White** if the message was sent plaintext
* **Green** if the message is successfully decrypted.
* **Red** if the message is marked as encrypted but fails to decrypt (e.g., due wrong passphrase or server converting ciphertext to lower case).

## Quick Start

1. **Install**:
   * Copy the userscript (`e2ee_userscript_v2.txt`) into a Tampermonkey (or similar) userscript environment.
2. **Open Lichess**:
   * Navigate to a Lichess game page.
3. **Set Passphrase**:
   * Use the "Set Passphrase" button in the top bar.
   * Any outgoing messages will now be encrypted if the toggle is on.
4. **Toggle Encryption**:
   * Turn the E2EE switch ON/OFF at any time.
5. **Chat**:
   * When ON, your messages will appear as `!e2ee!<ciphertext>` to anyone who does not have the same passphrase.
   * When OFF, chat messages remain in plain text.

## Detailed Mechanics & Safeguards

1. **Encryption**
   * The script intercepts outgoing Lichess chat messages at the WebSocket level.
   * If E2EE is **enabled** and a passphrase is set, it **AES-encrypts** the plaintext, adds a `!e2ee!` prefix, and sends that ciphertext.

2. **Markers**
   * Each outgoing message is prepended with `<X>` and appended with `<Y>` before encryption.
   * Ensures that, on decrypt, we can verify these markers exist. If they do not, we assume the passphrase is incorrect and mark the text red.

3. **Decryption**
   * Every 2 seconds, the script scans all text nodes in the DOM for `!e2ee!`.
   * Attempts to decrypt them.
   * **Green** if decryption + marker check succeeds, **red** if it fails.
   * If you initially had the wrong passphrase, then correct it, the script will retry and eventually show old messages in green if they can now be decrypted.

4. **UI Elements**
   * **Toggle**: A switch that turns encryption on/off.
   * **Passphrase**: A field to set the secret. Passphrase is stored (AES-encrypted) in `localStorage`.

5. **Storage**
   * The script uses your browser's `origin` (e.g., `https://lichess.org`) as a secondary key to encrypt configuration data and passphrase in `localStorage`.
   * If you clear your browser data, you lose the passphrase.

6. **Color Coding**
   * **Green**: Decrypted messages.
   * **Red**: Recognized encrypted messages that failed to decrypt.

7. **Security Considerations**
   * **Shared Passphrase**: Must be communicated securely outside of Lichess (e.g., via a secure channel).
   * **Local Script**: This is a client-side script. If you run it on a compromised browser or device, it can't protect your messages.
   * **Source**: The script is open for inspection, but keep in mind that Lichess's chat is otherwise not natively end-to-end encrypted.

8. **Limitations**
   * Only those using the same script and passphrase will see your messages in plaintext.
   * The script relies on DOM scanning for incoming messages. If Lichess changes how chat is rendered, minor fixes to the script might be required.
