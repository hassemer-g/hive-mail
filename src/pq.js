import pqclean from "./pqclean/pqclean.js";

export function valPrivPQkey(
    privKey,
    algorithm,
) {

    return privKey instanceof Uint8Array && (algorithm === "ml-kem-1024" ? privKey.length === 3168 : algorithm === "hqc-256" ? privKey.length === 7317 : false);
}

export function valPubPQkey(
    pubKey,
    algorithm,
) {

    return pubKey instanceof Uint8Array && (algorithm === "ml-kem-1024" ? pubKey.length === 1568 : algorithm === "hqc-256" ? pubKey.length === 7245 : false);
}

export async function createPQkeyPair(
    algorithm,
) {

    const { publicKey, privateKey } = await pqclean.kem.generateKeyPair(algorithm);

    const privKey = new Uint8Array(privateKey.export());
    const pubKey = new Uint8Array(publicKey.export());

    return { privKey, pubKey };
}

export function extractPQpubKey(
    privKey,
    algorithm,
) {

    const pubKeyLength = algorithm === "ml-kem-1024" ? 1568 : algorithm === "hqc-256" ? 7245 : NaN;
    const pubKeyOffset = algorithm === "ml-kem-1024" ? 1536 : algorithm === "hqc-256" ? 72 : NaN;

    const pubKey = privKey.slice(pubKeyOffset, pubKeyOffset + pubKeyLength);

    return pubKey;
}

export async function buildPQsharedSecret(
    pubKey,
    algorithm,
) {

    const pqPub = new pqclean.kem.PublicKey(algorithm, pubKey);
    const { key, encryptedKey } = await pqPub.generateKey();
    const sharedSecret = new Uint8Array(key);
    const encryptedSharedSecret = new Uint8Array(encryptedKey);

    return { sharedSecret, encryptedSharedSecret};
}

export async function retrievePQsharedSecret(
    privKey,
    encryptedKey,
    algorithm,
) {

    const pqPriv = new pqclean.kem.PrivateKey(algorithm, privKey);
    const key = await pqPriv.decryptKey(encryptedKey);
    const sharedSecret = new Uint8Array(key);

    return sharedSecret;
}
