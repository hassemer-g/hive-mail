import {
    concatUint8Arr,
} from "./utils.js";
import {
    createX25519KeyPair,
} from "./curves.js";
import {
    createPQkeyPair,
} from "./pq.js";

export function valHMprivKey(
    privKey,
) {
    return privKey instanceof Uint8Array && privKey.length === 10517;
}

export function valHMpubKey(
    pubKey,
) {
    return pubKey instanceof Uint8Array && pubKey.length === 8845;
}

export async function createHMkeyPair() {
    const [privX25519Key, pubX25519Key] = createX25519KeyPair();
    const [privKyberKey, pubKyberKey] = await createPQkeyPair("ml-kem-1024");
    const [privHQCkey, pubHQCkey] = await createPQkeyPair("hqc-256");
    return [concatUint8Arr(privX25519Key, privKyberKey, privHQCkey), concatUint8Arr(pubX25519Key, pubKyberKey, pubHQCkey)];
}
