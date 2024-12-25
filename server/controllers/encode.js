const crypto = require('crypto');

// Encryption Configuration
const ENCRYPTION_KEY = crypto.randomBytes(32); // 32 bytes for AES-256
const IV_LENGTH = 16; // AES block size for CBC mode
const ALGORITHM = 'aes-256-cbc';

/**
 * Encrypt text using AES-256-CBC algorithm.
 * @param {string} text - The plaintext to encrypt.
 * @returns {string} The encrypted text (IV + ciphertext in base64 format).
 */
function encryptText(text) {
    const iv = crypto.randomBytes(IV_LENGTH); // Generate random IV
    const cipher = crypto.createCipheriv(ALGORITHM, ENCRYPTION_KEY, iv);

    let encrypted = cipher.update(text, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    // Return IV and encrypted text as a single Base64 string
    return `${iv.toString('base64')}:${encrypted}`;

}

/**
 * Decrypt text encrypted with AES-256-CBC.
 * @param {string} encryptedText - The encrypted text (IV + ciphertext in base64 format).
 * @returns {string} The decrypted plaintext.
 */
function decryptText(encryptedText) {
    const parts = encryptedText.split(':');
    const iv = Buffer.from(parts[0], 'base64'); // Extract IV
    const encryptedData = parts[1]; // Extract ciphertext

    const decipher = crypto.createDecipheriv(ALGORITHM, ENCRYPTION_KEY, iv);

    let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
}

module.exports ={
    decryptText,
    encryptText
}