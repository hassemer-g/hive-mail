import { x25519 } from "./noble-curves/ed25519.mjs";

export function createX25519KeyPair() {

    const { secretKey, publicKey } = x25519.keygen();

    return { privKey: secretKey, pubKey: publicKey };
}

export function getX25519PubKey(privKey) {

    if (
        !(privKey instanceof Uint8Array)
        || privKey.length !== 32
    ) {
        throw new Error(`Invalid input passed to the "getX25519PubKey" function.`);
    }

    const pubKey = x25519.getPublicKey(privKey);

    return pubKey;
}

export function buildX25519SharedSecret(pubKey) {

    if (
        !(pubKey instanceof Uint8Array)
        || pubKey.length !== 32
    ) {
        throw new Error(`Invalid input passed to the "buildX25519SharedSecret" function.`);
    }

    const ephemeralPair = x25519.keygen();
    const sharedSecret = x25519.getSharedSecret(ephemeralPair.secretKey, pubKey);

    return { sharedSecret, encryptedSharedSecret: ephemeralPair.publicKey };
}

export function retrieveX25519SharedSecret(privKey, ephemeral) {

    if (
        !(privKey instanceof Uint8Array)
        || privKey.length !== 32
        || !(ephemeral instanceof Uint8Array)
        || ephemeral.length !== 32
    ) {
        throw new Error(`Invalid inputs passed to the "retrieveX25519SharedSecret" function.`);
    }

    const sharedSecret = x25519.getSharedSecret(privKey, ephemeral);

    return sharedSecret;
}
