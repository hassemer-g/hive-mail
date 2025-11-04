import {
    bytesToUtf8,
} from "./utils.js";
import {
    decodeBase91,
} from "./base91.js";
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
    privKey,
    msgSalt,
    timestamp,
    payloadBytes,
    Hs,
) {

    if (
        arguments.length !== 6
        || [recipientName, msgSalt].some(v => typeof v !== "string" || !v.trim())
        || !Number.isSafeInteger(timestamp)
        || !(payloadBytes instanceof Uint8Array)
        || payloadBytes.length < 16022
    ) {
        console.error(`Incorrect inputs to the "decryptMsg" function.`);
        return null;
    }

    try {

        const x25519Ephemeral = payloadBytes.slice(0, 32);
        const kyberEphemeral = payloadBytes.slice(32, 1600);
        const hqcEphemeral = payloadBytes.slice(1600, 16021);
        const ciphertext = payloadBytes.slice(16021);
        
        const privKeyBytes = decodeBase91(privKey);

        const privX25519Key = privKeyBytes.slice(0, 32);
        const privKyberKey = privKeyBytes.slice(32, 3200);
        const privHQCkey = privKeyBytes.slice(3200);

        let x25519SharedSecret = null;
        try {
            x25519SharedSecret = retrieveX25519SharedSecret(privX25519Key, x25519Ephemeral);
        } catch (err) {
            continue;
        }

        if (!(x25519SharedSecret instanceof Uint8Array)) {
            continue;
        }

        const pubX25519KeyBytes = getX25519PubKey(privX25519Key);

        let kyberSharedSecret = null;
        try {
            kyberSharedSecret = await retrievePQsharedSecret(privKyberKey, kyberEphemeral, "ml-kem-1024");
        } catch (err) {
            continue;
        }

        if (!(kyberSharedSecret instanceof Uint8Array)) {
            continue;
        }

        const pubKyberKeyBytes = extractPQpubKey(privKyberKey, "ml-kem-1024");

        let hqcSharedSecret = null;
        try {
            hqcSharedSecret = await retrievePQsharedSecret(privHQCkey, hqcEphemeral, "hqc-256");
        } catch (err) {
            continue;
        }

        if (!(hqcSharedSecret instanceof Uint8Array)) {
            continue;
        }

        const pubHQCkeyBytes = extractPQpubKey(privHQCkey, "hqc-256");

        const msgIdCode = `ჰM0 ${recipientName} ${timestamp} ${msgSalt} ${pubX25519KeyBytes.length} ${x25519SharedSecret.length} ${pubKyberKeyBytes.length} ${kyberSharedSecret.length} ${pubHQCkeyBytes.length} ${hqcSharedSecret.length} 0 0 0 0 0 0 0 0 0 0`;
        
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

        const decrypted3 = bytesToUtf8(decryptXChaCha20Poly1305(
            decrypted2,
            keypairs[5],
            keypairs[2],
        ));

        if (
            typeof decrypted3 === "string"
            && decrypted3.trim()
        ) {
            return decrypted3;
        }

        return null;

    } catch (err) {
        return null;
    }
}
