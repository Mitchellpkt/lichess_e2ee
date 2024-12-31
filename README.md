# Lichess end-to-end encryption (LE2EE)

A Tampermonkey (or similar) userscript that adds passphrase-based end-to-end encryption over Lichess chat, using **AES-256** (CBC mode via CryptoJS). Messages are encrypted locally in your browser before being sent, and only those who share your passphrase (and also have this script) can decrypt them.

Why? Lichess has server-side logic that strips emojis from chats, which is a bummer. With this extension, you can send emojis again. 😁

![image](https://github.com/user-attachments/assets/f0c88c88-9395-4dd8-ae28-3ddaa9fc2059)

---

## How It Works

1. **Outgoing Encryption**  
   When you enable E2EE and have set a passphrase, the script intercepts outgoing chat messages at the WebSocket level. Messages are encrypted, then sent with a `!e2ee!` prefix.

2. **Incoming Decryption**  
   The script periodically scans all chat messages for the `!e2ee!` prefix. If found, it attempts to decrypt those messages. Successful decryption appears in **green**, while failed decryption appears in **red**.

---

## Quick Start

1. **Install**  
   - Copy this userscript (e.g., `e2ee_userscript_v2.txt`) into Tampermonkey or a similar userscript manager.  
   - Save and enable the script.

2. **Visit Lichess**  
   - Go to [lichess.org](https://lichess.org/) and open any page with a chat (e.g., a game or a lobby).

3. **Set Passphrase**  
   - Click **"Set Passphrase"** in the top bar (added by the script).
   - Enter your shared secret. This passphrase must match on all devices/users who want to read your messages in plaintext.

4. **Toggle Encryption**  
   - Use the **E2EE** switch (also in the top bar) to turn encryption **ON** or **OFF** at any time.
   - When OFF, your messages are sent in plaintext as normal.

5. **Chat**  
   - With E2EE **ON**, your outgoing messages appear as `!e2ee!<ciphertext>` to anyone without the same passphrase/script.  
   - If they have the same passphrase, the text auto-decrypts and shows in green.

---

## Color Coding & Validation

- **Green**: The message was encrypted and successfully decrypted with your passphrase.  
- **Red**: The message appears encrypted (`!e2ee!`) but failed to decrypt (likely a wrong passphrase or garbled ciphertext).  
- **Default (White)**: The message was sent as plaintext.

---

## Detailed Mechanics & Safeguards

1. **Markers**  
   - Before encryption, each outgoing message is prepended with `<X>` and appended with `<Y>`.  
   - Upon decryption, the script verifies these markers to ensure the message was decrypted properly.

2. **DOM Scanning**  
   - Every 2 seconds, the script scans for `!e2ee!` strings in the chat area and attempts to decrypt them.  
   - If you correct an initially wrong passphrase, previous messages can become green if they are re-decrypted successfully.

3. **Local Storage**  
   - Your passphrase and script settings are saved in `localStorage`, AES-encrypted again using your current browser `origin` as an additional key.  
   - Clearing browser data removes your passphrase.

4. **Security Considerations**  
   - **Shared Secret**: You must share your passphrase *outside* Lichess chat to ensure security.  
   - **Local Script**: The encryption happens entirely in your browser, but if your device is compromised, messages could still be exposed.  
   - **Lichess Server**: The server only sees ciphertext, not plaintext, but it still logs the encrypted messages.

5. **Limitations**  
   - All participants must be running this userscript and using the *same passphrase* to see each other’s messages in plaintext.  
   - If Lichess changes how chat messages are rendered, minor updates to the script may be required.

---

## Contributing

- The script is open source. Feel free to submit issues and pull requests.  
- Use at your own risk; this is offered without warranty.

