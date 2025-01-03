// ==UserScript==
// @name         E2EE messages over Lichess chat
// @namespace    http://tampermonkey.net/
// @version      0.9.1
// @description  Encrypts messages before sending, and decrypts chat box
// @match        https://lichess.org/*
// @grant        none
// @require      https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js
// ==/UserScript==

(function() {
    'use strict';

    // Toggle debug for console output
    const DEBUG = true;
    const debug = (...args) => DEBUG && console.log('[E2EE]', ...args);

    // Persistent keys
    const CONFIG_STORAGE_KEY       = 'lichessE2EEConfig';
    const PASSPHRASE_STORAGE_KEY   = 'lichessE2EEPassphrase';

    // Markers for verifying decryption correctness
    const MARKER_START = 'X^';
    const MARKER_END   = '#Y';

    // Dynamic E2EE tag
    const E2EE_TAG = '!e!';

    // Defaults
    let isEncryptionEnabled = false;
    let passphrase = '';
    let encodingChoice = 'c'; // default to zBase32

    // Available encodings (extended with 'c' for CJK)
    const ENCODING_OPTIONS = {
        b: 'Base64',
        h: 'Hex',
        z: 'Z-Base32',
        c: 'CJK',   // new! packs ~14 bits into one Unicode character
    };

    // Encodings details
    const CJK_BASE = 0x4E00;      // Start of common CJK block
    const CJK_BITS_PER_CHAR = 14; // We'll store 14 bits per code point
    const CJK_MAX_VALUE = (1 << CJK_BITS_PER_CHAR) - 1; // 16383
    const ZBASE32_ALPHABET = 'ybndrfg8ejkmcpqxot1uwisza345h769';


    // Helper: convert a CryptoJS WordArray to a normal byte array plus bitLength
    function wordArrayToBytes(wordArray) {
        const { words, sigBytes } = wordArray;
        const bytes = new Uint8Array(sigBytes);
        for (let i = 0; i < sigBytes; i++) {
            bytes[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
        }
        return { bytes, bitLength: sigBytes * 8 };
    }


    // ─────────────────────────────────────────────────────────────────────────────
    // ─── LOAD/SAVE CONFIG AND PASSPHRASE ────────────────────────────────────────
    // ─────────────────────────────────────────────────────────────────────────────

    function encryptStoredData(data, secret) {
        return CryptoJS.AES.encrypt(JSON.stringify(data), secret).toString();
    }

    function decryptStoredData(encryptedData, secret) {
        try {
            const bytes = CryptoJS.AES.decrypt(encryptedData, secret);
            return JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
        } catch {
            return null;
        }
    }

    function loadSavedConfig() {
        try {
            const data = localStorage.getItem(CONFIG_STORAGE_KEY);
            if (data) {
                const decrypted = decryptStoredData(data, window.origin);
                if (decrypted) {
                    isEncryptionEnabled = decrypted.isEnabled || false;
                    // If 'encoding' is present, load that; else keep default 'z'
                    if (decrypted.encoding && ENCODING_OPTIONS[decrypted.encoding]) {
                        encodingChoice = decrypted.encoding;
                    }
                }
            }
        } catch {}
    }

    function loadSavedPassphrase() {
        try {
            const data = localStorage.getItem(PASSPHRASE_STORAGE_KEY);
            if (data) {
                const decrypted = decryptStoredData(data, window.origin);
                if (decrypted) {
                    passphrase = decrypted;
                }
            }
        } catch {}
    }

    function saveConfiguration(overrides = {}) {
        const config = {
            isEnabled: isEncryptionEnabled,
            encoding: encodingChoice,
            ...overrides
        };
        const encrypted = encryptStoredData(config, window.origin);
        localStorage.setItem(CONFIG_STORAGE_KEY, encrypted);
    }

    function savePassphrase(newPass) {
        const encrypted = encryptStoredData(newPass, window.origin);
        localStorage.setItem(PASSPHRASE_STORAGE_KEY, encrypted);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ─── UI CREATION FOR TOGGLE, PASSPHRASE, AND ENCODING ───────────────────────
    // ─────────────────────────────────────────────────────────────────────────────

    function handlePassphraseSubmission(inputEl) {
        const newPass = inputEl.value.trim();
        if (!newPass) {
            alert('Passphrase cannot be empty!');
            return;
        }
        passphrase = newPass;
        savePassphrase(newPass);
        // Obscure the entered value with asterisks
        inputEl.value = '*'.repeat(newPass.length);
        inputEl.style.display = 'none';
    }

    function createE2EEControls() {
        const siteButtons = document.querySelector('.site-buttons');
        if (!siteButtons) {
            setTimeout(createE2EEControls, 500);
            return;
        }
        if (document.querySelector('#e2ee-control')) return;

        loadSavedConfig();
        loadSavedPassphrase();

        // Container with subtle divider on the left
        const container = document.createElement('div');
        container.id = 'e2ee-control';
        container.style.display = 'flex';
        container.style.alignItems = 'center';
        container.style.gap = '0.5rem';
        container.style.borderLeft = '1px solid #666';
        container.style.marginLeft = '8px';
        container.style.paddingLeft = '8px';

        // ─────────────────────────────────────────────────────────────────────────
        // Toggle (on/off)
        // ─────────────────────────────────────────────────────────────────────────
        const toggleContainer = document.createElement('div');
        toggleContainer.style.display = 'flex';
        toggleContainer.style.alignItems = 'center';
        toggleContainer.style.gap = '0.4rem';

        const toggleSwitch = document.createElement('label');
        toggleSwitch.style.position = 'relative';
        toggleSwitch.style.display = 'inline-block';
        toggleSwitch.style.width = '50px';
        toggleSwitch.style.height = '24px';

        const toggleInput = document.createElement('input');
        toggleInput.type = 'checkbox';
        toggleInput.style.opacity = '0';
        toggleInput.style.width = '0';
        toggleInput.style.height = '0';
        toggleInput.checked = isEncryptionEnabled;

        const toggleSlider = document.createElement('span');
        toggleSlider.style.position = 'absolute';
        toggleSlider.style.cursor = 'pointer';
        toggleSlider.style.top = '0';
        toggleSlider.style.left = '0';
        toggleSlider.style.right = '0';
        toggleSlider.style.bottom = '0';
        toggleSlider.style.backgroundColor = '#ccc';
        toggleSlider.style.transition = '0.4s';
        toggleSlider.style.borderRadius = '24px';
        toggleSlider.style.padding = '2px';
        toggleSlider.style.boxSizing = 'border-box';
        toggleSlider.style.display = 'flex';
        toggleSlider.style.alignItems = 'center';

        const toggleHandle = document.createElement('span');
        toggleHandle.style.height = '20px';
        toggleHandle.style.width = '20px';
        toggleHandle.style.borderRadius = '50%';
        toggleHandle.style.backgroundColor = 'white';
        toggleHandle.style.transition = '0.4s';

        const toggleLabel = document.createElement('span');
        toggleLabel.textContent = 'E2EE';
        toggleLabel.style.fontWeight = 'bold';
        toggleLabel.style.color = '#bababa';

        function updateSliderStyles() {
            if (toggleInput.checked) {
                toggleSlider.style.backgroundColor = '#629924'; // green
                toggleHandle.style.transform = 'translateX(26px)';
            } else {
                toggleSlider.style.backgroundColor = '#ccc';
                toggleHandle.style.transform = 'translateX(0)';
            }
        }
        updateSliderStyles();

        toggleInput.addEventListener('change', () => {
            isEncryptionEnabled = toggleInput.checked;
            saveConfiguration();
            updateSliderStyles();
            // If turned on but no passphrase set, prompt for one
            if (isEncryptionEnabled && !passphrase) {
                passphraseInput.style.display = 'block';
                submitArrow.style.display = 'inline-block';
                passphraseInput.value = '';
                passphraseInput.focus();
            }
        });

        toggleSlider.appendChild(toggleHandle);
        toggleSwitch.appendChild(toggleInput);
        toggleSwitch.appendChild(toggleSlider);

        toggleContainer.appendChild(toggleSwitch);
        toggleContainer.appendChild(toggleLabel);

        // ─────────────────────────────────────────────────────────────────────────
        // Passphrase input
        // ─────────────────────────────────────────────────────────────────────────
        const passphraseInput = document.createElement('input');
        passphraseInput.type = 'password';
        passphraseInput.placeholder = 'Enter passphrase';
        passphraseInput.style.padding = '0.3rem 0.5rem';
        passphraseInput.style.backgroundColor = '#302e2c';
        passphraseInput.style.border = '1px solid #484541';
        passphraseInput.style.borderRadius = '3px';
        passphraseInput.style.color = '#bababa';
        passphraseInput.style.width = '150px';
        passphraseInput.style.display = 'none';

        // Submit arrow (button)
        const submitArrow = document.createElement('button');
        submitArrow.textContent = '➜';
        submitArrow.style.marginLeft = '4px';
        submitArrow.style.padding = '0.3rem 0.5rem';
        submitArrow.style.borderRadius = '3px';
        submitArrow.style.cursor = 'pointer';
        submitArrow.style.backgroundColor = '#302e2c';
        submitArrow.style.border = '1px solid #484541';
        submitArrow.style.color = '#bababa';
        submitArrow.style.display = 'none';

        // Toggle passphrase input link
        const setPassphraseButton = document.createElement('a');
        setPassphraseButton.textContent = 'Set Passphrase';
        setPassphraseButton.className = 'link';
        setPassphraseButton.style.fontWeight = 'bold';
        setPassphraseButton.style.color = '#bababa';
        setPassphraseButton.style.cursor = 'pointer';
        setPassphraseButton.style.textDecoration = 'none';

        setPassphraseButton.addEventListener('click', () => {
            const currentlyHidden = (passphraseInput.style.display === 'none');
            passphraseInput.style.display = currentlyHidden ? 'block' : 'none';
            submitArrow.style.display    = currentlyHidden ? 'inline-block' : 'none';
            if (currentlyHidden) {
                passphraseInput.value = '';
                passphraseInput.focus();
            }
        });

        passphraseInput.addEventListener('keydown', e => {
            if (e.key === 'Enter') {
                e.preventDefault();
                handlePassphraseSubmission(passphraseInput);
            }
        });

        submitArrow.addEventListener('click', () => {
            handlePassphraseSubmission(passphraseInput);
        });

        // Clicking outside closes passphrase input
        document.addEventListener('click', e => {
            if (!container.contains(e.target)) {
                passphraseInput.style.display = 'none';
                submitArrow.style.display = 'none';
            }
        });

        // ─────────────────────────────────────────────────────────────────────────
        // Encoding dropdown
        // ─────────────────────────────────────────────────────────────────────────
        const encodingLabel = document.createElement('span');
        encodingLabel.textContent = 'Encoding:';
        encodingLabel.style.color = '#bababa';
        encodingLabel.style.fontWeight = 'bold';

        const encodingSelect = document.createElement('select');
        encodingSelect.style.backgroundColor = '#302e2c';
        encodingSelect.style.border = '1px solid #484541';
        encodingSelect.style.color = '#bababa';
        encodingSelect.style.padding = '0.2rem';
        encodingSelect.style.borderRadius = '3px';

        // Populate the <select> with b/h/z/c
        Object.entries(ENCODING_OPTIONS).forEach(([val, label]) => {
            const opt = document.createElement('option');
            opt.value = val;
            opt.textContent = label;
            if (val === encodingChoice) {
                opt.selected = true;
            }
            encodingSelect.appendChild(opt);
        });

        encodingSelect.addEventListener('change', () => {
            encodingChoice = encodingSelect.value; // b/h/z/c
            saveConfiguration();
        });

        // ─────────────────────────────────────────────────────────────────────────
        // Add everything into container
        // ─────────────────────────────────────────────────────────────────────────
        container.appendChild(toggleContainer);
        container.appendChild(setPassphraseButton);
        container.appendChild(passphraseInput);
        container.appendChild(submitArrow);

        // A small gap or separator for the next label
        const spacer = document.createElement('span');
        spacer.textContent = ' | ';
        spacer.style.color = '#666';
        container.appendChild(spacer);

        container.appendChild(encodingLabel);
        container.appendChild(encodingSelect);

        // Insert in siteButtons
        const searchComponent = siteButtons.querySelector('.search-component');
        const challengeButton = siteButtons.querySelector('a[href^="/challenge"]');
        if (searchComponent) {
            siteButtons.insertBefore(container, searchComponent);
        } else if (challengeButton) {
            siteButtons.insertBefore(container, challengeButton);
        } else {
            siteButtons.appendChild(container);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ─── ENCRYPT/DECRYPT DISPATCH BASED ON ENCODING ─────────────────────────────
    // ─────────────────────────────────────────────────────────────────────────────

    // 1) AES encrypt the message, giving us .ciphertext, .salt, .iv
    // 2) Encode each piece with the chosen method (b/h/z/c)
    // 3) Prefix with "!e2ee!x|" where x ∈ {b,h,z,c}
    function encryptMessage(message) {
        if (!isEncryptionEnabled || !passphrase) return message;
        try {
            const wrapped = MARKER_START + message + MARKER_END;
            const encrypted = CryptoJS.AES.encrypt(wrapped, passphrase);

            // Convert each piece depending on chosen encoding
            const ctEncoded = encodeData(encrypted.ciphertext, encodingChoice);
            const sEncoded  = encodeData(encrypted.salt,       encodingChoice);
            const ivEncoded = encodeData(encrypted.iv,         encodingChoice);

            // Example: "!e2ee!z|salt:iv:cipher"
            return E2EE_TAG + encodingChoice + '|' + sEncoded + ':' + ivEncoded + ':' + ctEncoded;
        } catch {
            return message;
        }
    }

    function decryptMessage(fullText) {
        if (!passphrase) return null;
        try {
            // Must start with "!e2ee!"
            if (!fullText.startsWith(E2EE_TAG)) return null;

            // Next character after "!e2ee!" is encoding (b/h/z/c), then '|'
            const encChar = fullText.charAt(E2EE_TAG.length);
            if (!ENCODING_OPTIONS[encChar]) return null; // invalid
            const remainder = fullText.slice(E2EE_TAG.length + 2); // skip "x|"

            // remainder => "saltEnc:ivEnc:cipherEnc"
            const [sEnc, ivEnc, ctEnc] = remainder.split(':');
            if (!sEnc || !ivEnc || !ctEnc) return null;

            // Decode each
            const salt       = decodeData(sEnc,  encChar);
            const iv         = decodeData(ivEnc, encChar);
            const ciphertext = decodeData(ctEnc, encChar);
            if (!salt || !iv || !ciphertext) return null;

            // Rebuild
            const cipherParams = CryptoJS.lib.CipherParams.create({
                ciphertext,
                salt,
                iv
            });

            // Decrypt
            const bytes = CryptoJS.AES.decrypt(cipherParams, passphrase);
            const plaintext = bytes.toString(CryptoJS.enc.Utf8);
            if (!plaintext.startsWith(MARKER_START) || !plaintext.endsWith(MARKER_END)) {
                return null;
            }
            return plaintext.slice(MARKER_START.length, plaintext.length - MARKER_END.length);
        } catch {
            return null;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ─── INDIVIDUAL ENCODING ROUTINES ───────────────────────────────────────────
    // ─────────────────────────────────────────────────────────────────────────────

    // Encodes a CryptoJS WordArray using b/h/z/c
    function encodeData(wordArray, method) {
        switch (method) {
            case 'b': // Base64
                return wordArray.toString(CryptoJS.enc.Base64)
                    .replace(/\+/g, '-').replace(/\//g, '_');
                // (optional) replace +/ with -_ if you want URL-safe

            case 'h': // Hex
                return wordArray.toString(CryptoJS.enc.Hex);

            case 'z': // Z-Base-32
                return zBase32Encode(wordArray);

            case 'c': // CJK
                return cjkEncode(wordArray);

            default:
                return zBase32Encode(wordArray);
        }
    }

    // Decodes a string to a CryptoJS WordArray using b/h/z/c
    function decodeData(str, method) {
        switch (method) {
            case 'b': // Base64
                // Reverse any +/ replacements if you did them
                str = str.replace(/-/g, '+').replace(/_/g, '/');
                return CryptoJS.enc.Base64.parse(str);

            case 'h': // Hex
                return CryptoJS.enc.Hex.parse(str);

            case 'z': // Z-Base-32
                return zBase32Decode(str);

            case 'c': // CJK
                return cjkDecode(str);

            default:
                return zBase32Decode(str);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ─── BASE32 (LOWERCASE-ONLY) HELPERS ────────────────────────────────────────
    // ─────────────────────────────────────────────────────────────────────────────

    function zBase32Encode(wordArray) {
        // First convert WordArray to regular bytes
        const words = wordArray.words;
        const sigBytes = wordArray.sigBytes;
        const bytes = new Uint8Array(sigBytes);

        for (let i = 0; i < sigBytes; i++) {
            bytes[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
        }

        // Convert to binary string
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += bytes[i].toString(2).padStart(8, '0');
        }

        // Encode 5 bits at a time
        let result = '';
        for (let i = 0; i < binary.length; i += 5) {
            const chunk = binary.slice(i, i + 5).padEnd(5, '0');
            const value = parseInt(chunk, 2);
            result += ZBASE32_ALPHABET[value];
        }

        return result;
    }

    function zBase32Decode(encoded) {
        // Convert to binary
        let binary = '';
        for (let i = 0; i < encoded.length; i++) {
            const index = ZBASE32_ALPHABET.indexOf(encoded[i]);
            if (index === -1) continue;
            binary += index.toString(2).padStart(5, '0');
        }

        // Process 8 bits at a time to get bytes
        const bytes = [];
        for (let i = 0; i < binary.length - 7; i += 8) {
            const chunk = binary.slice(i, i + 8);
            bytes.push(parseInt(chunk, 2));
        }

        // Convert bytes back to WordArray
        const words = [];
        for (let i = 0; i < bytes.length; i += 4) {
            let word = 0;
            for (let j = 0; j < 4 && i + j < bytes.length; j++) {
                word |= bytes[i + j] << (24 - j * 8);
            }
            words.push(word);
        }

        return CryptoJS.lib.WordArray.create(words, bytes.length);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ─── CJK HELPERS ─────────────────────────────────────────────────────
    // ─────────────────────────────────────────────────────────────────────────────
    //
    // We'll encode 14 bits per code point to stay within U+4E00..U+9FFF (which
    // has room for ~20,992 code points). 2^14 = 16384, so each code point
    // can represent a value from 0..16383. This yields more density than base32.
    //
    // The offset chosen (CJK_BASE = 0x4E00) is the start of the "CJK Unified
    // Ideographs" block. We only go up to 0x4E00 + 16383 = 0x8FFF range, which
    // is well within the total block size. Unused code points near the top
    // of the block remain unused.
    //
    // --------------------------------------------------------------------------

    function cjkEncode(wordArray) {
    const { bytes, bitLength } = wordArrayToBytes(wordArray);

    // Convert bytes to binary string
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += bytes[i].toString(2).padStart(8, '0');
    }

    // Store the original bit length as first 14 bits
    const lengthPrefix = bitLength.toString(2).padStart(CJK_BITS_PER_CHAR, '0');

    // Pad the data bits if needed
    if (binary.length % CJK_BITS_PER_CHAR !== 0) {
        binary = binary.padEnd(
            binary.length + (CJK_BITS_PER_CHAR - (binary.length % CJK_BITS_PER_CHAR)),
            '0'
        );
    }

    // Combine length prefix with data
    binary = lengthPrefix + binary;

    // Encode to CJK characters
    let result = '';
    for (let i = 0; i < binary.length; i += CJK_BITS_PER_CHAR) {
        const chunk = binary.slice(i, i + CJK_BITS_PER_CHAR);
        const value = parseInt(chunk, 2);
        result += String.fromCharCode(CJK_BASE + value);
    }
    return result;
}

function cjkDecode(encoded) {
    // Convert to binary string
    let binary = '';
    for (let i = 0; i < encoded.length; i++) {
        const codePoint = encoded.charCodeAt(i);
        const value = codePoint - CJK_BASE;
        if (value < 0 || value > CJK_MAX_VALUE) continue;
        binary += value.toString(2).padStart(CJK_BITS_PER_CHAR, '0');
    }

    // Extract the original length from first character
    const originalBitLength = parseInt(binary.slice(0, CJK_BITS_PER_CHAR), 2);
    binary = binary.slice(CJK_BITS_PER_CHAR);

    // Truncate to original length
    binary = binary.slice(0, originalBitLength);

    // Convert back to bytes
    const bytes = [];
    for (let i = 0; i < binary.length; i += 8) {
        const chunk = binary.slice(i, i + 8);
        if (chunk.length < 8) break;
        bytes.push(parseInt(chunk, 2));
    }

    // Convert to WordArray
    const words = [];
    for (let i = 0; i < bytes.length; i += 4) {
        let word = 0;
        for (let j = 0; j < 4 && i + j < bytes.length; j++) {
            word |= bytes[i + j] << (24 - j * 8);
        }
        words.push(word);
    }

    return CryptoJS.lib.WordArray.create(words, bytes.length);
}

    // ─────────────────────────────────────────────────────────────────────────────
    // ─── WEBSOCKET & CHAT INPUT INTERCEPTION (OUTGOING ENCRYPTION) ──────────────
    // ─────────────────────────────────────────────────────────────────────────────
    function monitorCommunication() {
        const originalWebSocket = window.WebSocket;
        window.WebSocket = function(url, protocols) {
            const ws = new originalWebSocket(url, protocols);
            const originalSend = ws.send;
            ws.send = function(data) {
                if (typeof data === 'string' && data.includes('"t":"talk"')) {
                    try {
                        const parsed = JSON.parse(data);
                        if (parsed.t === 'talk') {
                            parsed.d = encryptMessage(parsed.d);
                            data = JSON.stringify(parsed);
                        }
                    } catch {}
                }
                return originalSend.call(ws, data);
            };
            return ws;
        };

        // Also intercept the standard chat input
        const chatObserver = new MutationObserver(() => {
            const chatInput = document.querySelector('.mchat__say');
            if (chatInput && !chatInput.dataset.e2eeMonitored) {
                chatInput.dataset.e2eeMonitored = 'true';
                chatInput.addEventListener('keydown', function(e) {
                    if (e.key === 'Enter' && !e.shiftKey) {
                        this.value = encryptMessage(this.value);
                    }
                }, true);
            }
        });

        chatObserver.observe(document.body, { childList: true, subtree: true });
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ─── PERIODIC SCANNING FOR "!e2ee!" MESSAGES ────────────────────────────────
    // ─────────────────────────────────────────────────────────────────────────────
    function findTextNodesContaining(substring, root) {
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
        const results = [];
        let node;
        while ((node = walker.nextNode())) {
            if (node.nodeValue.includes(substring)) results.push(node);
        }
        return results;
    }

    function periodicDecryptionScanner() {
        setInterval(() => {
            const textNodes = findTextNodesContaining(E2EE_TAG, document.body);
            textNodes.forEach(node => {
                const parentEl = node.parentElement;
                if (!parentEl) return;

                // Preserve the original ciphertext
                const rawText = parentEl.dataset.e2eeRaw || node.nodeValue.trim();
                parentEl.dataset.e2eeRaw = rawText;

                const decrypted = decryptMessage(rawText);
                if (decrypted) {
                    node.nodeValue = decrypted;
                    parentEl.style.color = 'green';
                } else {
                    node.nodeValue = rawText;
                    parentEl.style.color = 'red';
                }
            });
        }, 2000);
    }

    // ─────────────────────────────────────────────────────────────────────────────
    // ─── INIT ───────────────────────────────────────────────────────────────────
    // ─────────────────────────────────────────────────────────────────────────────
    function init() {
        createE2EEControls();
        monitorCommunication();
        periodicDecryptionScanner();
        debug('Initialized E2EE Chat (with CJK encoding option)');
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
