// Cryptography implementation using elliptic and crypto-js libraries
const ec = new elliptic.ec('secp256k1');
const CryptoJS = window.CryptoJS;

// Key Generation
function generateKeyPair() {
    const keyPair = ec.genKeyPair();
    const publicKey = keyPair.getPublic('hex');
    const privateKey = keyPair.getPrivate('hex');
    
    document.getElementById('public-key-display').textContent = publicKey;
    document.getElementById('private-key-display').textContent = privateKey;
    
    document.getElementById('keys-container').style.display = 'block';
    document.getElementById('download-keys').disabled = false;
    document.getElementById('save-keys-csv').disabled = false;
}

// Encryption

function encryptMessage() {
    const recipientPublicKey = document.getElementById('recipient-key').value;
    const plaintext = document.getElementById('plaintext').value;
    
    if (!recipientPublicKey || !plaintext) {
        alert('Please enter both recipient public key and message');
        return;
    }
    
    try {
        const senderKeyPair = ec.genKeyPair();
        const recipientPublicKeyPoint = ec.keyFromPublic(recipientPublicKey, 'hex');
        
        const sharedSecret = senderKeyPair.derive(recipientPublicKeyPoint.getPublic());
        const sharedSecretHex = sharedSecret.toString(16);
        
        const key = CryptoJS.enc.Hex.parse(sharedSecretHex.slice(0, 32));
        const iv = CryptoJS.lib.WordArray.random(16);
        
        const encrypted = CryptoJS.AES.encrypt(plaintext, key, { iv: iv });
        
        const payload = {
            iv: iv.toString(),
            ciphertext: encrypted.toString(),
            ephemeralPublicKey: senderKeyPair.getPublic('hex')
        };
        
        const encryptedPayload = btoa(JSON.stringify(payload));
        
        document.getElementById('ciphertext-display').textContent = encryptedPayload;
        document.getElementById('encrypted-result').style.display = 'block';
        document.getElementById('save-encrypted-csv').disabled = false;
    } catch (error) {
        console.error('Encryption error:', error);
        alert('Encryption failed. Check your inputs.');
    }
}

// Decryption

function decryptMessage() {
    const ciphertext = document.getElementById('ciphertext').value;
    const privateKey = document.getElementById('private-key-input').value;
    
    if (!ciphertext || !privateKey) {
        alert('Please enter both ciphertext and private key');
        return;
    }
    
    try {
        const decodedPayload = JSON.parse(atob(ciphertext));
        const { iv, ciphertext: encryptedData, ephemeralPublicKey } = decodedPayload;
        
        const privateKeyPair = ec.keyFromPrivate(privateKey, 'hex');
        const senderPublicKeyPoint = ec.keyFromPublic(ephemeralPublicKey, 'hex').getPublic();
        
        const sharedSecret = privateKeyPair.derive(senderPublicKeyPoint);
        const sharedSecretHex = sharedSecret.toString(16);
        
        const key = CryptoJS.enc.Hex.parse(sharedSecretHex.slice(0, 32));
        const ivWordArray = CryptoJS.enc.Hex.parse(iv);
        
        const decrypted = CryptoJS.AES.decrypt(encryptedData, key, { iv: ivWordArray });
        const decryptedText = decrypted.toString(CryptoJS.enc.Utf8);
        
        document.getElementById('decrypted-text').textContent = decryptedText;
        document.getElementById('decrypted-result').style.display = 'block';
        document.getElementById('save-decrypted-csv').disabled = false;
    } catch (error) {
        console.error('Decryption error:', error);
        alert('Decryption failed. Check your inputs or the encrypted payload.');
    }
}

// Tab Navigation
function setupTabs() {
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const tabId = tab.getAttribute('data-tab');
            
            // Update active tab
            tabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            
            // Show active content
            const sections = document.querySelectorAll('.section');
            sections.forEach(section => section.classList.remove('active'));
            document.getElementById(`section-${tabId}`).classList.add('active');
        });
    });

    // History tabs
    const historyTabs = document.querySelectorAll('.tab-secondary');
    historyTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const tabId = tab.getAttribute('data-history-tab');
            
            // Update active tab
            historyTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            
            // Show active content
            const sections = document.querySelectorAll('.history-section');
            sections.forEach(section => section.classList.remove('active'));
            document.getElementById(`history-${tabId}`).classList.add('active');
        });
    });
}

// Copy functionality
function setupCopyButtons() {
    const copyButtons = document.querySelectorAll('.copy-btn');
    copyButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetId = button.getAttribute('data-copy');
            const text = document.getElementById(`${targetId}-display`).textContent;
            
            navigator.clipboard.writeText(text)
                .then(() => showToast('Copied to clipboard!'))
                .catch(err => console.error('Failed to copy:', err));
        });
    });

    // Additional copy buttons
    document.getElementById('copy-encrypted')?.addEventListener('click', () => {
        const text = document.getElementById('ciphertext-display').textContent;
        navigator.clipboard.writeText(text)
            .then(() => showToast('Encrypted text copied to clipboard!'))
            .catch(err => console.error('Failed to copy:', err));
    });

    document.getElementById('copy-decrypted')?.addEventListener('click', () => {
        const text = document.getElementById('decrypted-text').textContent;
        navigator.clipboard.writeText(text)
            .then(() => showToast('Decrypted text copied to clipboard!'))
            .catch(err => console.error('Failed to copy:', err));
    });
}

// Toast notification
function showToast(message, duration = 3000) {
    const toast = document.getElementById('toast');
    document.getElementById('toast-message').textContent = message;
    
    toast.classList.remove('hidden');
    toast.classList.add('visible');
    
    setTimeout(() => {
        toast.classList.remove('visible');
        toast.classList.add('hidden');
    }, duration);
}

// Download functionality
function setupDownloadButtons() {
    document.getElementById('download-keys')?.addEventListener('click', () => {
        const publicKey = document.getElementById('public-key-display').textContent;
        const privateKey = document.getElementById('private-key-display').textContent;
        
        const content = `Public Key: ${publicKey}\nPrivate Key: ${privateKey}`;
        downloadFile('ecc-keys.txt', content);
    });

    document.getElementById('download-encrypted')?.addEventListener('click', () => {
        const ciphertext = document.getElementById('ciphertext-display').textContent;
        downloadFile('encrypted-message.txt', ciphertext);
    });
}

// CSV Export
function setupCSVExport() {
    document.getElementById('save-keys-csv')?.addEventListener('click', () => {
        const publicKey = document.getElementById('public-key-display').textContent;
        const privateKey = document.getElementById('private-key-display').textContent;
        
        const csvContent = `"Public Key","Private Key"\n"${publicKey}","${privateKey}"`;
        downloadFile('ecc-keys.csv', csvContent);
    });

    document.getElementById('save-encrypted-csv')?.addEventListener('click', () => {
        const recipientKey = document.getElementById('recipient-key').value;
        const plaintext = document.getElementById('plaintext').value;
        const ciphertext = document.getElementById('ciphertext-display').textContent;
        
        const csvContent = `"Recipient Public Key","Original Message","Encrypted Message"\n"${recipientKey}","${plaintext}","${ciphertext}"`;
        downloadFile('encrypted-message.csv', csvContent);
    });

    document.getElementById('save-decrypted-csv')?.addEventListener('click', () => {
        const privateKey = document.getElementById('private-key-input').value.substring(0, 20) + '...';
        const ciphertext = document.getElementById('ciphertext').value;
        const decryptedText = document.getElementById('decrypted-text').textContent;
        
        const csvContent = `"Private Key (partial)","Encrypted Message","Decrypted Message"\n"${privateKey}","${ciphertext}","${decryptedText}"`;
        downloadFile('decrypted-message.csv', csvContent);
    });
}

// Helper function to download a file
function downloadFile(filename, content) {
    const element = document.createElement('a');
    element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(content));
    element.setAttribute('download', filename);
    
    element.style.display = 'none';
    document.body.appendChild(element);
    
    element.click();
    
    document.body.removeChild(element);
    showToast(`${filename} downloaded successfully!`);
}

// Event Listeners
document.addEventListener('DOMContentLoaded', () => {
    // Set up event listeners for main functionality
    document.getElementById('generate-keys')?.addEventListener('click', generateKeyPair);
    document.getElementById('encrypt-message')?.addEventListener('click', encryptMessage);
    document.getElementById('decrypt-message')?.addEventListener('click', decryptMessage);
    
    // Set up UI interactions
    setupTabs();
    setupCopyButtons();
    setupDownloadButtons();
    setupCSVExport();
});
