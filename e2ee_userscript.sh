// ==UserScript==
// @name         Lichess E2EE Chat
// @namespace    http://tampermonkey.net/
// @version      0.5
// @description  Subtle grouping for E2EE controls
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
    const CONFIG_STORAGE_KEY = 'lichessE2EEConfig';
    const PASSPHRASE_STORAGE_KEY = 'lichessE2EEPassphrase';

    // Markers for verifying decryption correctness
    const MARKER_START = '<X2>';
    const MARKER_END = '<Y2>';

    let isEncryptionEnabled = false;
    let passphrase = '';

    // --- LocalStorage encryption/decryption helpers ---
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

    // --- Load/save config and passphrase ---
    function loadSavedConfig() {
        try {
            const data = localStorage.getItem(CONFIG_STORAGE_KEY);
            if (data) {
                const decrypted = decryptStoredData(data, window.origin);
                if (decrypted) {
                    isEncryptionEnabled = decrypted.isEnabled || false;
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
        const config = { isEnabled: isEncryptionEnabled, ...overrides };
        const encrypted = encryptStoredData(config, window.origin);
        localStorage.setItem(CONFIG_STORAGE_KEY, encrypted);
    }
    function savePassphrase(newPass) {
        const encrypted = encryptStoredData(newPass, window.origin);
        localStorage.setItem(PASSPHRASE_STORAGE_KEY, encrypted);
    }

    // --- Handle passphrase submission ---
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

    // --- UI creation for toggle and passphrase ---
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

        // Subtle dividing line and a little left padding
        container.style.borderLeft = '1px solid #666';
        container.style.marginLeft = '8px';
        container.style.paddingLeft = '8px';

        // Toggle container
        const toggleContainer = document.createElement('div');
        toggleContainer.style.display = 'flex';
        toggleContainer.style.alignItems = 'center';
        toggleContainer.style.gap = '0.4rem';

        // Switch (slider) wrapper
        const toggleSwitch = document.createElement('label');
        toggleSwitch.style.position = 'relative';
        toggleSwitch.style.display = 'inline-block';
        toggleSwitch.style.width = '50px';
        toggleSwitch.style.height = '24px';

        // The actual checkbox input
        const toggleInput = document.createElement('input');
        toggleInput.type = 'checkbox';
        toggleInput.style.opacity = '0';
        toggleInput.style.width = '0';
        toggleInput.style.height = '0';
        toggleInput.checked = isEncryptionEnabled;

        // Slider background
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

        // Slider "handle"
        const toggleHandle = document.createElement('span');
        toggleHandle.style.height = '20px';
        toggleHandle.style.width = '20px';
        toggleHandle.style.borderRadius = '50%';
        toggleHandle.style.backgroundColor = 'white';
        toggleHandle.style.transition = '0.4s';

        // Label
        const toggleLabel = document.createElement('span');
        toggleLabel.textContent = 'E2EE';
        toggleLabel.style.fontWeight = 'bold';
        toggleLabel.style.color = '#bababa';

        // Update slider style based on isEncryptionEnabled
        function updateSliderStyles() {
            if (toggleInput.checked) {
                toggleSlider.style.backgroundColor = '#629924'; // green
                toggleHandle.style.transform = 'translateX(26px)';
            } else {
                toggleSlider.style.backgroundColor = '#ccc';
                toggleHandle.style.transform = 'translateX(0)';
            }
        }

        updateSliderStyles(); // initial look

        // When toggling E2EE
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

        // Assemble the slider
        toggleSlider.appendChild(toggleHandle);
        toggleSwitch.appendChild(toggleInput);
        toggleSwitch.appendChild(toggleSlider);

        // Put them together
        toggleContainer.appendChild(toggleSwitch);
        toggleContainer.appendChild(toggleLabel);

        // Passphrase input
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
        submitArrow.style.display = 'none'; // will show up alongside passphrase

        // Toggle passphrase input with link
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

        // Press Enter to submit passphrase
        passphraseInput.addEventListener('keydown', e => {
            if (e.key === 'Enter') {
                e.preventDefault();
                handlePassphraseSubmission(passphraseInput);
            }
        });

        // Click arrow to submit passphrase
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

        container.appendChild(toggleContainer);
        container.appendChild(setPassphraseButton);
        container.appendChild(passphraseInput);
        container.appendChild(submitArrow);

        // Put the new container near search or challenge buttons if possible
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

    // --- Encryption & decryption ---
    function encryptMessage(message) {
        if (!isEncryptionEnabled || !passphrase) return message;
        try {
            const wrapped = MARKER_START + message + MARKER_END;
            const cipher = CryptoJS.AES.encrypt(wrapped, passphrase).toString();
            return `!e2ee!${cipher}`;
        } catch {
            return message;
        }
    }
    function decryptMessage(encryptedMessage) {
        if (!passphrase) return null;
        try {
            const ciphertext = encryptedMessage.replace('!e2ee!', '');
            const bytes = CryptoJS.AES.decrypt(ciphertext, passphrase);
            const plaintext = bytes.toString(CryptoJS.enc.Utf8);
            if (!plaintext.startsWith(MARKER_START) || !plaintext.endsWith(MARKER_END)) {
                return null;
            }
            return plaintext.slice(MARKER_START.length, plaintext.length - MARKER_END.length);
        } catch {
            return null;
        }
    }

    // --- WebSocket & chat input interception (outgoing encryption) ---
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

    // --- Periodic scanning for "!e2ee!" messages ---
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
            const textNodes = findTextNodesContaining('!e2ee!', document.body);
            textNodes.forEach(node => {
                const parentEl = node.parentElement;
                if (!parentEl) return;

                // Preserve original ciphertext
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

    // --- Initialize ---
    function init() {
        createE2EEControls();
        monitorCommunication();
        periodicDecryptionScanner();
        debug('Initialized E2EE Chat');
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
