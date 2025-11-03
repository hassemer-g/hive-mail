import {
    concatBytes,
    utf8ToBytes,
} from "./utils.js";
import {
    doHashing,
    derivMult,
} from "./deriv.js";
import {
    valPubPQkey,
} from "./pq.js";

export function derivForMsg(
    msgIdCode,
    recipientPubX25519Key,
    recipientPubKyberKey,
    recipientPubHQCkey,
    x25519SharedSecret,
    kyberSharedSecret,
    hqcSharedSecret,
    Hs,
) {

    const salt = doHashing(
        concatBytes(utf8ToBytes(msgIdCode), recipientPubX25519Key, recipientPubKyberKey, recipientPubHQCkey),
        Hs,
        128,
    );

    return derivMult(
        doHashing(
            concatBytes(x25519SharedSecret, kyberSharedSecret, hqcSharedSecret, salt),
            Hs,
            16320,
            3,
        ),
        salt,
        [24, 12, 24, 32, 32, 32],
        Hs,
    );
}
