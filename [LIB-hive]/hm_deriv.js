import { sha3_512 } from "@noble/hashes/sha3";
import { hkdf } from "@noble/hashes/hkdf";

import { doHashing } from "../[LIB]/hashing.js";
import {
    bytesToBase91,
} from "../[LIB]/custom_base91.js";


// ==================================================================== //


// Build keys, nonces and passwords for message encryption pipeline
export function derivForMsg(
    txCode, // string
    recipientPubMemoKey, // string
    recipientPubPQkey, // string
    memoSharedSecret, // Uint8Array, 64 bytes
    pqSharedSecret, // Uint8Array, 32 bytes
) {

    // Ensure correct inputs
    if (!(memoSharedSecret instanceof Uint8Array) || memoSharedSecret.length !== 64) {
        throw new Error("\"memoSharedSecret\" is expected to be 64-byte Uint8Array.");
    }
    if (!(pqSharedSecret instanceof Uint8Array) || pqSharedSecret.length !== 32) {
        throw new Error("\"pqSharedSecret\" is expected to be 32-byte Uint8Array.");
    }

    // Derive the salt
    const salt = doHashing(`${txCode}—${bytesToBase91(memoSharedSecret)}—${recipientPubMemoKey}`);

    // Derive the password
    const passw = doHashing(`${bytesToBase91(pqSharedSecret)}—${recipientPubPQkey}—${bytesToBase91(salt)}`);

    // Derive key for symmetric encryption
    const keyForEncrypt = hkdf(
        sha3_512,
        passw,
        salt,
        doHashing(`key—${txCode}—${bytesToBase91(memoSharedSecret)}—${bytesToBase91(pqSharedSecret)}`),
        32,
    );

    // Derive nonce for symmetric encryption
    const nonceForEncrypt = hkdf(
        sha3_512,
        passw,
        salt,
        doHashing(`nonce—${txCode}—${bytesToBase91(memoSharedSecret)}—${bytesToBase91(pqSharedSecret)}`),
        24,
    );

    /*
    // Debugging
    if (!salt || !passw || !keyForEncrypt || !nonceForEncrypt) {
        throw new Error(`Derivation failed.`);
    }
    console.log("Salt:", bytesToBase91(salt));
    console.log("Password:", bytesToBase91(passw));
    console.log("Key for symmetric encryption:", bytesToBase91(keyForEncrypt));
    console.log("Nonce for symmetric encryption:", bytesToBase91(nonceForEncrypt));
    */

    return { keyForEncrypt, nonceForEncrypt };
}













