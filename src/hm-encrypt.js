import {
    concatBytes,
    utf8ToBytes,
} from "./utils.js";
import {
    encodeBase91,
} from "./base91.js";
import {
    encryptXChaCha20Poly1305,
} from "./xchacha20-poly1305.js";
import {
    encryptAesGcmSiv,
} from "./aes-gcm-siv.js";
import {
    encryptXSalsaPoly1305,
} from "./xsalsa-poly1305.js";
import {
    buildPQsharedSecret,
} from "./pq.js";
import { buildX25519SharedSecret } from "./x25519.js";
import { derivForMsg } from "./hm-deriv.js";

export async function encryptMsg(
    plaintext,
    recipientName,
    recipientPubHMkey,
    Hs,
    doNotUsePq = false,
) {

    const recipientPubX25519Key = recipientPubHMkey.slice(0, 32);
    const recipientPubKyberKey = recipientPubHMkey.slice(32, 1600);
    const recipientPubHQCkey = recipientPubHMkey.slice(1600);

    const { sharedSecret: x25519SharedSecret, encryptedSharedSecret: x25519Ephemeral } = buildX25519SharedSecret(recipientPubX25519Key);

    let kyberSharedSecret = new Uint8Array(0), kyberEphemeral = new Uint8Array(0), hqcSharedSecret = new Uint8Array(0), hqcEphemeral = new Uint8Array(0);
    if (!doNotUsePq) {
        ({ sharedSecret: kyberSharedSecret, encryptedSharedSecret: kyberEphemeral } = await buildPQsharedSecret(recipientPubKyberKey, "ml-kem-1024"));
        ({ sharedSecret: hqcSharedSecret, encryptedSharedSecret: hqcEphemeral } = await buildPQsharedSecret(recipientPubHQCkey, "hqc-256"));
    }

    const msgInfo = utf8ToBytes(`ჰM0 ${recipientName} ${""} ${""} ${""} ${""} ${""} ${recipientPubX25519Key.length} ${x25519Ephemeral.length} ${x25519SharedSecret.length} ${recipientPubKyberKey.length} ${kyberEphemeral.length} ${kyberSharedSecret.length} ${recipientPubHQCkey.length} ${hqcEphemeral.length} ${hqcSharedSecret.length} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0`);

    const keypairs = derivForMsg(
        msgInfo,
        Hs,
        recipientPubX25519Key,
        x25519Ephemeral,
        x25519SharedSecret,
        recipientPubKyberKey,
        kyberEphemeral,
        kyberSharedSecret,
        recipientPubHQCkey,
        hqcEphemeral,
        hqcSharedSecret,
    );

    const ciphertext1 = encryptXChaCha20Poly1305(
        plaintext,
        keypairs[5],
        keypairs[2],
    );

    let finalCiphertext;
    if (doNotUsePq) {
        finalCiphertext = ciphertext1;

    } else {

        const ciphertext2 = encryptAesGcmSiv(
            ciphertext1,
            keypairs[4],
            keypairs[1],
        );

        finalCiphertext = encryptXSalsaPoly1305(
            ciphertext2,
            keypairs[3],
            keypairs[0],
        );
    }

    const payload = concatBytes(
        x25519Ephemeral,
        kyberEphemeral,
        hqcEphemeral,
        finalCiphertext,
    );

    return `${doNotUsePq ? "0m" : "0M"}` + encodeBase91(payload);
}
