import { x25519 } from "./noble-curves/ed25519.mjs";

export function createX25519KeyPair() {

    const { secretKey, publicKey } = x25519.keygen();

    return { privKey: secretKey, pubKey: publicKey };
}

export function getX25519PubKey(privKey) {

    const pubKey = x25519.getPublicKey(privKey);

    return pubKey;
}

export function buildX25519SharedSecret(pubKey) {

    const ephemeralPair = x25519.keygen();
    const sharedSecret = x25519.getSharedSecret(ephemeralPair.secretKey, pubKey);

    return { sharedSecret, encryptedSharedSecret: ephemeralPair.publicKey };
}

export function retrieveX25519SharedSecret(privKey, ephemeral) {

    const sharedSecret = x25519.getSharedSecret(privKey, ephemeral);

    return sharedSecret;
}
