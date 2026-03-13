import {
    concatUint8Arr,
    utf8ToBytes,
    buildPatternArr,
    wipeUint8Arr,
} from "./utils.js";
import {
    myHash,
} from "./deriv.js";
import {
    decryptAesGcmSiv,
    layeredDecrypt,
} from "./ciphers.js";
import {
    retrieveX25519SharedSecret,
    getX25519PubKey,
} from "./curves.js";
import {
    extractPQpubKey,
    retrievePQsharedSecret,
} from "./pq.js";

export async function decryptMsg(
    recipientName,
    privKeyBytes,
    payloadBytes,
) {
    try {
        const prefix = payloadBytes.subarray(0, 4);
        const prefixStr = (String((prefix[0] | prefix[1] << 8 | prefix[2] << 16 | prefix[3] << 24) >>> 0)).padStart(10, "0");

        const HM_version = prefixStr.slice(0, 3);
        const HM_mode = prefixStr.slice(3, 7);

        let useKyber, inputIsFile;
        if (HM_mode === "0001") {
            useKyber = false;
            inputIsFile = false;
        } else if (HM_mode === "0002") {
            useKyber = true;
            inputIsFile = false;
        } else if (HM_mode === "0005") {
            useKyber = false;
            inputIsFile = true;
        } else if (HM_mode === "0006") {
            useKyber = true;
            inputIsFile = true;
        } else {
            console.error(`Payload is corrupted!`);
            return [null, null];
        }

        const x25519Ephemeral = payloadBytes.subarray(4, 36);

        let ciphertext, kyberEphemeral = new Uint8Array(0);
        if (useKyber) {
            kyberEphemeral = payloadBytes.subarray(36, 1604);
            ciphertext = payloadBytes.subarray(1604);

        } else {
            ciphertext = payloadBytes.subarray(36);
        }

        if ((String(ciphertext.length).slice(-3)).padStart(3, "0") !== prefixStr.slice(-3)) {
            console.error(`Payload is corrupted! Incorrect ciphertext length.`);
            return [null, null];
        }

        const privX25519Key = privKeyBytes.subarray(0, 32);
        const privKyberKey = privKeyBytes.subarray(32);

        const x25519SharedSecret = retrieveX25519SharedSecret(privX25519Key, x25519Ephemeral);
        if (!(x25519SharedSecret instanceof Uint8Array && x25519SharedSecret.length === 32)) {
            return [null, null];
        }

        let kyberSharedSecret = new Uint8Array(0);
        if (useKyber) {
            kyberSharedSecret = await retrievePQsharedSecret(privKyberKey, kyberEphemeral, "ml-kem-1024");

            if (!(kyberSharedSecret instanceof Uint8Array && kyberSharedSecret.length === 32)) {
                return [null, null];
            }
        }

        const pubX25519Key = getX25519PubKey(privX25519Key);
        const pubKyberKey = extractPQpubKey(privKyberKey, "ml-kem-1024");
        wipeUint8Arr(privKeyBytes);

        const keysAndNonces = myHash(
            concatUint8Arr(x25519SharedSecret, kyberSharedSecret, utf8ToBytes(`ჰM-${HM_version} ${HM_mode} ${recipientName} ${pubX25519Key.length} ${x25519Ephemeral.length} ${x25519SharedSecret.length} ${pubKyberKey.length} ${kyberEphemeral.length} ${kyberSharedSecret.length} ჰ`), pubX25519Key, x25519Ephemeral, pubKyberKey, kyberEphemeral),
            [...buildPatternArr([24, 32], 10), 12, 32],
            1000,
            256,
            undefined,
            true,
        );
        wipeUint8Arr(x25519SharedSecret, kyberSharedSecret);

        const kLen = keysAndNonces.length;

        const decrypted = decryptAesGcmSiv(
            ciphertext,
            keysAndNonces[kLen - 1],
            keysAndNonces[kLen - 2],
        );

        layeredDecrypt(
            decrypted,
            keysAndNonces.slice(0, -2),
        );

        if (
            decrypted instanceof Uint8Array
            && decrypted.length
        ) {
            return [
                decrypted,
                inputIsFile,
            ];
        }

        return [null, null];

    } catch (err) {
        return [null, null];
    }
}
