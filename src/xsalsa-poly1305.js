import { xsalsa20poly1305 } from "./noble-ciphers/salsa.mjs";

export function encryptXSalsaPoly1305(
    plaintext,
    key,
    nonce,
) {

    if (!(plaintext instanceof Uint8Array)) {
        throw new Error("Plaintext is supposed to be a Uint8Array.");
    }
    if (!(key instanceof Uint8Array) || key.length !== 32) {
        throw new Error("Key is supposed to be 32-byte Uint8Array.");
    }
    if (!(nonce instanceof Uint8Array) || nonce.length !== 24) {
        throw new Error("Nonce is supposed to be 24-byte Uint8Array.");
    }

    const cipher = xsalsa20poly1305(key, nonce);

    return cipher.encrypt(plaintext);
}

export function decryptXSalsaPoly1305(
    ciphertext,
    key,
    nonce,
) {

    if (!(ciphertext instanceof Uint8Array)) {
        throw new Error("Ciphertext is supposed to be a Uint8Array.");
    }
    if (!(key instanceof Uint8Array) || key.length !== 32) {
        throw new Error("Key is supposed to be 32-byte Uint8Array.");
    }
    if (!(nonce instanceof Uint8Array) || nonce.length !== 24) {
        throw new Error("Nonce is supposed to be 24-byte Uint8Array.");
    }

    const cipher = xsalsa20poly1305(key, nonce);

    return cipher.decrypt(ciphertext);
}
