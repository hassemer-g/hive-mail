import {
    concatUint8Arr,
    utf8ToBytes,
    wipeUint8Arr,
} from "./utils.js";
import {
    doHashing,
} from "./deriv.js";
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

export async function decryptMsg(
    recipientName,
    privKeyBytes,
    payloadBytes,
    Hs,
) {
    try {
        const prefix = payloadBytes.subarray(0, 4);
        const prefixStr = (String((prefix[0] | prefix[1] << 8 | prefix[2] << 16 | prefix[3] << 24) >>> 0)).padStart(10, "0");
        const HM_version = prefixStr.slice(0, 3);
        const HM_mode = prefixStr.slice(3, 7);

        let doNotUsePq = false;
        if (HM_mode === "0000") { }
        else if (HM_mode === "0001") { doNotUsePq = true; }
        else {
            console.error(`Payload is corrupted!`);
            return null;
        }

        const x25519Ephemeral = payloadBytes.subarray(4, 36);

        let ciphertext, kyberEphemeral = new Uint8Array(0), hqcEphemeral = new Uint8Array(0);
        if (doNotUsePq) {
            ciphertext = payloadBytes.subarray(36);
        } else {
            kyberEphemeral = payloadBytes.subarray(36, 1604);
            hqcEphemeral = payloadBytes.subarray(1604, 16025);
            ciphertext = payloadBytes.subarray(16025);
        }

        if ((String(ciphertext.length).slice(-3)).padStart(3, "0") !== prefixStr.slice(-3)) {
            console.error(`Payload is corrupted! Incorrect ciphertext length.`);
            return null;
        }

        const privX25519Key = privKeyBytes.subarray(0, 32);
        const privKyberKey = privKeyBytes.subarray(32, 3200);
        const privHQCkey = privKeyBytes.subarray(3200);

        const x25519SharedSecret = retrieveX25519SharedSecret(privX25519Key, x25519Ephemeral);
        if (!(x25519SharedSecret instanceof Uint8Array) || x25519SharedSecret.length !== 32) { return null; }

        let kyberSharedSecret = new Uint8Array(0), hqcSharedSecret = new Uint8Array(0);
        if (!doNotUsePq) {

            kyberSharedSecret = await retrievePQsharedSecret(privKyberKey, kyberEphemeral, "ml-kem-1024");
            if (!(kyberSharedSecret instanceof Uint8Array) || kyberSharedSecret.length !== 32) { return null; }

            hqcSharedSecret = await retrievePQsharedSecret(privHQCkey, hqcEphemeral, "hqc-256");
            if (!(hqcSharedSecret instanceof Uint8Array) || hqcSharedSecret.length !== 64) { return null; }
        }

        const pubX25519KeyBytes = getX25519PubKey(privX25519Key);
        const pubKyberKeyBytes = extractPQpubKey(privKyberKey, "ml-kem-1024");
        const pubHQCkeyBytes = extractPQpubKey(privHQCkey, "hqc-256");
        wipeUint8Arr(privKeyBytes);

        const keypairs = doHashing(
            concatUint8Arr(x25519SharedSecret, kyberSharedSecret, hqcSharedSecret, utf8ToBytes(`ჰM-${HM_version} ${HM_mode} ${recipientName} ${pubX25519KeyBytes.length} ${x25519Ephemeral.length} ${x25519SharedSecret.length} ${pubKyberKeyBytes.length} ${kyberEphemeral.length} ${kyberSharedSecret.length} ${pubHQCkeyBytes.length} ${hqcEphemeral.length} ${hqcSharedSecret.length} ჰ`), pubX25519KeyBytes, x25519Ephemeral, pubKyberKeyBytes, kyberEphemeral, pubHQCkeyBytes, hqcEphemeral),
            Hs,
            [24, 12, 24, 32, 32, 32],
            1000,
            true,
        );
        wipeUint8Arr(x25519SharedSecret, kyberSharedSecret, hqcSharedSecret);

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

        if (
            finalDecrypted
            && finalDecrypted instanceof Uint8Array
            && finalDecrypted.length
        ) {
            return [
                finalDecrypted,
            ];
        }

        return null;

    } catch (err) {
        return null;
    }
}
