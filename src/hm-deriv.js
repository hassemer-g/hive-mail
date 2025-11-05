import {
    concatBytes,
} from "./utils.js";
import {
    doHashing,
    derivMult,
} from "./deriv.js";

export function derivForMsg(
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
) {

    const salt = doHashing(
        concatBytes(msgInfo, recipientPubX25519Key, x25519Ephemeral, recipientPubKyberKey, kyberEphemeral, recipientPubHQCkey, hqcEphemeral),
        Hs,
        128,
    );

    return derivMult(
        doHashing(
            concatBytes(x25519SharedSecret, kyberSharedSecret, hqcSharedSecret, salt),
            Hs,
            16320,
            10,
        ),
        salt,
        [24, 12, 24, 32, 32, 32],
        Hs,
    );
}
