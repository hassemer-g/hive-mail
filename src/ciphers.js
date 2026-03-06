import { gcmsiv } from "./noble-ciphers/aes.js";
import { xchacha20 } from "./noble-ciphers/chacha.js";

export function encryptAesGcmSiv(
    plaintext,
    key,
    nonce,
) {
    return gcmsiv(key, nonce).encrypt(plaintext);
}

export function decryptAesGcmSiv(
    ciphertext,
    key,
    nonce,
) {
    return gcmsiv(key, nonce).decrypt(ciphertext);
}

export function layeredEncrypt(
    target,
    keysAndNonces,
) {
    const len = keysAndNonces.length;
    for (let i = 0; i < len; i += 2) {
        xchacha20(keysAndNonces[i + 1], keysAndNonces[i], target, target);
    }
    return target;
}

export function layeredDecrypt(
    target,
    keysAndNonces,
) {
    for (let i = keysAndNonces.length - 2; i >= 0; i -= 2) {
        xchacha20(keysAndNonces[i + 1], keysAndNonces[i], target, target);
    }
    return target;
}
