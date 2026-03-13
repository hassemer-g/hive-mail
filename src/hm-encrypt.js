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
    encryptAesGcmSiv,
    layeredEncrypt,
} from "./ciphers.js";
import {
    buildPQsharedSecret,
    valPubPQkey,
} from "./pq.js";
import { buildX25519SharedSecret } from "./curves.js";

export async function encryptMsg(
    plaintext,
    recipientName,
    recipientPubHMkey,
    useKyber = true,
    inputIsFile = false,
) {
    const HM_version = "001";

    let HM_mode;
    if (!useKyber && !inputIsFile) { HM_mode = "0001" }
    else if (useKyber && !inputIsFile) { HM_mode = "0002" }
    else if (!useKyber && inputIsFile) { HM_mode = "0005" }
    else if (useKyber && inputIsFile) { HM_mode = "0006" }

    const pubX25519Key = recipientPubHMkey.subarray(0, 32);
    const pubKyberKey = recipientPubHMkey.subarray(32);

    const [x25519SharedSecret, x25519Ephemeral] = buildX25519SharedSecret(pubX25519Key);

    let kyberSharedSecret = new Uint8Array(0), kyberEphemeral = new Uint8Array(0);
    if (useKyber) {
        [kyberSharedSecret, kyberEphemeral] = await buildPQsharedSecret(pubKyberKey, "ml-kem-1024");
    }

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

    layeredEncrypt(
        plaintext,
        keysAndNonces.slice(0, -2),
    );

    const finalCiphertext = encryptAesGcmSiv(
        plaintext,
        keysAndNonces[kLen - 1],
        keysAndNonces[kLen - 2],
    );

    const prefixNumber = Number(HM_version + HM_mode + (String(finalCiphertext.length).slice(-3)).padStart(3, "0"));

    return concatUint8Arr(
        Uint8Array.of(
            prefixNumber,
            prefixNumber >>> 8,
            prefixNumber >>> 16,
            prefixNumber >>> 24,
        ),
        x25519Ephemeral,
        kyberEphemeral,
        finalCiphertext,
    );
}
