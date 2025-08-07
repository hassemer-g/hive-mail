import { sha3_512 } from "@noble/hashes/sha3";
import { hkdf } from "@noble/hashes/hkdf";

import {
    bytesToBase91,
} from "../[LIB]/custom_base91.js";
import { doHashing } from "../[LIB]/hashing.js";
import { doScrypt } from "../[LIB]/scrypt_async.js";


// ==================================================================== //


// Derive key, nonce and passwords for save file encryption / decryption (outputs in Uint8Array)
export async function derivForSaveFile(
    saveFilePassw, // string
    saveFilePIN, // string
    salt, // string
) {

    // Hash imported elements
    const hashedSaveFilePassw = doHashing(saveFilePassw);
    const hashedSaveFilePIN = doHashing(saveFilePIN);
    const hashedSalt = doHashing(salt);

    // Derive the pre-password
    const prePassw = doHashing(`${bytesToBase91(hashedSaveFilePassw)}—${bytesToBase91(hashedSaveFilePIN)}—${bytesToBase91(hashedSalt)}`);

    // Derive the final password using Scrypt
    console.time("Derivation of password for save file");
    const passw = await doScrypt(
        prePassw,
        hashedSalt,
    );
    console.timeEnd("Derivation of password for save file");

    // Derive key (returns Uint8Array)
    const keyForEncrypt = hkdf(
        sha3_512,
        passw,
        hashedSalt,
        doHashing(`key—${salt}—${bytesToBase91(prePassw)}`),
        32,
    );

    // Derive nonce (returns Uint8Array)
    const nonceForEncrypt = hkdf(
        sha3_512,
        passw,
        hashedSalt,
        doHashing(`nonce—${salt}—${bytesToBase91(prePassw)}`),
        24,
    );

    /*
    // Debugging
    if (!prePassw || !passw || !keyForEncrypt || !nonceForEncrypt) {
        throw new Error(`Derivation failed.`);
    }
    console.log("Pre-password for save file:", bytesToBase91(prePassw));
    console.log("Final password for save file:", bytesToBase91(passw));
    console.log("Key for save file symmetric encryption:", bytesToBase91(keyForEncrypt));
    console.log("Nonce for save file symmetric encryption:", bytesToBase91(nonceForEncrypt));
    */

    return { keyForEncrypt, nonceForEncrypt };
}








