import pqclean from "pqclean";

import {
    customBase91CharSet,
} from "./charsets.js";
import {
    bytesFromBase91,
} from "./custom_base91.js";
import { validateStringCharSet } from "./validate_string_charset.js";


// ==================================================================== //


// Validate private Post-Quantum key
export function validatePrivPQkey(
    privKey, // string, in Base91
) {

    if (!validateStringCharSet(privKey, customBase91CharSet)) return false;

    try {
        const keyBytes = bytesFromBase91(privKey);
        return keyBytes.length === 3168;
    } catch (err) {
        return false; // In case bytesFromBase91 throws a malformed input
    }
}


// Validate public Post-Quantum key
export function validatePubPQkey(
    pubKey, // string, in Base91
) {

    if (!validateStringCharSet(pubKey, customBase91CharSet)) return false;

    try {
        const keyBytes = bytesFromBase91(pubKey);
        return keyBytes.length === 1568;
    } catch (err) {
        return false; // In case bytesFromBase91 throws a malformed input
    }
}


// Derive random post-quantum keypair (both returned in Uint8Array)
export async function derivePQkeyPair(
    // no inputs required
) {

    const { publicKey, privateKey } = await pqclean.kem.generateKeyPair("ml-kem-1024");

    // Get Uint8Array of each key
    const privKey = new Uint8Array(privateKey.export());
    const pubKey = new Uint8Array(publicKey.export());

    if (!(privKey instanceof Uint8Array) || privKey.length !== 3168) {
        throw new Error("Private Post-Quantum Key must be 3168-byte Uint8Array.");
    }
    if (!(pubKey instanceof Uint8Array) || pubKey.length !== 1568) {
        throw new Error("Public Post-Quantum Key must be 1568-byte Uint8Array.");
    }

    return { privKey, pubKey }; // both Uint8Array
}


// Extract public key from Kyber-1024 private key (both input & output Uint8Array)
export function extractKyberPublicKey(
    privKey, // Uint8Array
) {

    if (!(privKey instanceof Uint8Array)) {
        throw new Error("Input Private Post-Quantum Key should be a Uint8Array.");
    }

    const privKeyLength = 3168; // For ml-kem-1024
    const pubKeyLength = 1568;
    const pubKeyOffset = 1536;

    if (privKey.length !== privKeyLength) {
        throw new Error(`Input Private Post-Quantum Key should have ${privKeyLength} bytes. Input length: ${privKey.length}.`);
    }

    // Correctly slice public key at known position
    const pubKey = privKey.slice(pubKeyOffset, pubKeyOffset + pubKeyLength);

    if (pubKey.length !== pubKeyLength) {
        throw new Error(`Public Post-Quantum Key should have ${pubKeyLength} bytes. Output length: ${pubKey.length}.`);
    }

    return pubKey; // Uint8Array
}






