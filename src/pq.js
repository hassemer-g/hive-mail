import pqclean from "./pqclean/pqclean.js";

export function valPubPQkey(
    pubKey,
    algorithm,
) {
    return pubKey instanceof Uint8Array
        && (
            (algorithm === "ml-kem-1024" && pubKey.length === 1568)
            || (algorithm === "hqc-256" && pubKey.length === 7245)
        );
}

export async function createPQkeyPair(
    algorithm,
) {
    const { publicKey, privateKey } = await pqclean.kem.generateKeyPair(algorithm);
    return [new Uint8Array(privateKey.export()), new Uint8Array(publicKey.export())];
}

export function extractPQpubKey(
    privKey,
    algorithm,
) {
    const pubKeyOffset = algorithm === "hqc-256" ? 72 : 1536;
    return privKey.slice(pubKeyOffset, pubKeyOffset + (algorithm === "hqc-256" ? 7245 : 1568));
}

export async function buildPQsharedSecret(
    pubKey,
    algorithm,
) {
    const pqPub = new pqclean.kem.PublicKey(algorithm, pubKey);
    const { key, encryptedKey } = await pqPub.generateKey();
    return [new Uint8Array(key), new Uint8Array(encryptedKey)];
}

export async function retrievePQsharedSecret(
    privKey,
    encryptedKey,
    algorithm,
) {
    const pqPriv = new pqclean.kem.PrivateKey(algorithm, privKey);
    return new Uint8Array(await pqPriv.decryptKey(encryptedKey));
}
