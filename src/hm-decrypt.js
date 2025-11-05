import {
    utf8ToBytes,
    bytesToUtf8,
} from "./utils.js";
import {
    decryptXChaCha20Poly1305,
} from "./xchacha20-poly1305.js";
import {
    decryptAesGcmSiv,
} from "./aes-gcm-siv.js";
import {
    decryptXSalsaPoly1305,
} from "./xsalsa-poly1305.js";
import {
    extractPQpubKey,
    retrievePQsharedSecret,
} from "./pq.js";
import {
    retrieveX25519SharedSecret,
    getX25519PubKey,
} from "./x25519.js";
import { derivForMsg } from "./hm-deriv.js";

export async function decryptMsg(
    recipientName,
    privKeyBytes,
    msgSalt,
    timestamp,
    payloadBytes,
    Hs,
    doNotUsePq = false,
) {

    if (
        [recipientName, msgSalt].some(v => typeof v !== "string" || !v.trim())
        || !Number.isSafeInteger(timestamp)
        || !(payloadBytes instanceof Uint8Array)
        || (!doNotUsePq && payloadBytes.length < 16022)
    ) {
        console.error(`Incorrect inputs to the "decryptMsg" function.`);
        return null;
    }

    try {

        const x25519Ephemeral = payloadBytes.slice(0, 32);

        let kyberEphemeral = new Uint8Array(0), hqcEphemeral = new Uint8Array(0);
        let ciphertext;
        if (doNotUsePq) {
            ciphertext = payloadBytes.slice(32);
        } else {
            kyberEphemeral = payloadBytes.slice(32, 1600);
            hqcEphemeral = payloadBytes.slice(1600, 16021);
            ciphertext = payloadBytes.slice(16021);
        }

        const privX25519Key = privKeyBytes.slice(0, 32);
        const privKyberKey = privKeyBytes.slice(32, 3200);
        const privHQCkey = privKeyBytes.slice(3200);

        const x25519SharedSecret = retrieveX25519SharedSecret(privX25519Key, x25519Ephemeral);
        if (!(x25519SharedSecret instanceof Uint8Array)) {
            return null;
        }

        let kyberSharedSecret = new Uint8Array(0), hqcSharedSecret = new Uint8Array(0);
        if (!doNotUsePq) {

            kyberSharedSecret = await retrievePQsharedSecret(privKyberKey, kyberEphemeral, "ml-kem-1024");
            if (!(kyberSharedSecret instanceof Uint8Array)) {
                return null;
            }

            hqcSharedSecret = await retrievePQsharedSecret(privHQCkey, hqcEphemeral, "hqc-256");
            if (!(hqcSharedSecret instanceof Uint8Array)) {
                return null;
            }
        }

        const pubX25519KeyBytes = getX25519PubKey(privX25519Key);
        const pubKyberKeyBytes = extractPQpubKey(privKyberKey, "ml-kem-1024");
        const pubHQCkeyBytes = extractPQpubKey(privHQCkey, "hqc-256");

        const msgIdCode = utf8ToBytes(`ჰM0 ${recipientName} ${timestamp} ${msgSalt} ${pubX25519KeyBytes.length} ${x25519SharedSecret.length} ${x25519Ephemeral.length} ${pubKyberKeyBytes.length} ${kyberSharedSecret.length} ${kyberEphemeral.length} ${pubHQCkeyBytes.length} ${hqcSharedSecret.length} ${hqcEphemeral.length} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0`);

        const keypairs = derivForMsg(
            msgIdCode,
            pubX25519KeyBytes,
            pubKyberKeyBytes,
            pubHQCkeyBytes,
            x25519SharedSecret,
            kyberSharedSecret,
            hqcSharedSecret,
            Hs,
        );

        let finalDecrypted;
        if (doNotUsePq) {

            finalDecrypted = decryptXChaCha20Poly1305(
                ciphertext,
                keypairs[5],
                keypairs[2],
            );

        } else {

            const decrypted1 = decryptXSalsaPoly1305(
                ciphertext,
                keypairs[3],
                keypairs[0],
            );

            const decrypted2 = decryptAesGcmSiv(
                decrypted1,
                keypairs[4],
                keypairs[1],
            );

            finalDecrypted = decryptXChaCha20Poly1305(
                decrypted2,
                keypairs[5],
                keypairs[2],
            );
        }

        const decryptedStr = bytesToUtf8(finalDecrypted);

        if (
            typeof decryptedStr === "string"
            && decryptedStr.trim()
        ) {
            return decryptedStr;
        }

        return null;

    } catch (err) {
        return null;
    }
}
