import { x25519 } from "./noble-curves/ed25519.js";

export function createX25519KeyPair() {
    const { secretKey, publicKey } = x25519.keygen();
    return [secretKey, publicKey];
}

export function getX25519PubKey(privKey) {
    return x25519.getPublicKey(privKey);
}

export function buildX25519SharedSecret(pubKey) {
    const ephemeralPair = x25519.keygen();
    return [x25519.getSharedSecret(ephemeralPair.secretKey, pubKey), ephemeralPair.publicKey];
}

export function retrieveX25519SharedSecret(privKey, ephemeral) {
    return x25519.getSharedSecret(privKey, ephemeral);
}
