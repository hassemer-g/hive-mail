import {
    concatUint8Arr,
} from "./utils.js";
import {
    createX25519KeyPair,
} from "./x25519.js";
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

    const { privKey: privX25519Key, pubKey: pubX25519Key } = createX25519KeyPair();
    const { privKey: privKyberKey, pubKey: pubKyberKey } = await createPQkeyPair("ml-kem-1024");
    const { privKey: privHQCkey, pubKey: pubHQCkey } = await createPQkeyPair("hqc-256");

    const privKey = concatUint8Arr(privX25519Key, privKyberKey, privHQCkey);
    const pubKey = concatUint8Arr(pubX25519Key, pubKyberKey, pubHQCkey);

    return { privKey, pubKey };
}
