import { scryptAsync } from "@noble/hashes/scrypt";

import { doHashing } from "./hashing.js";


// ==================================================================== //


// Perform key derivation using Scrypt (async)
export async function doScrypt(
    passw0, // Uint8Array, non-empty string, integer, object or array
    rawSalt, // Uint8Array, non-empty string, integer, object or array
    outputLength = 64,
) {

    // Preliminary hashing, returns Uint8Array
    const passw1 = doHashing(passw0);
    const salt = doHashing(rawSalt);

    // Derivation using Scrypt
    let p = -1;
    const scryptOutput = await scryptAsync(
        passw1,
        salt,
        {
            N: 2 ** 20, // CPU cost factor (must be power of 2)
            r: 8, // block size
            p: 1, // parallelisation
            dkLen: outputLength, // output length in bytes
            onProgress: x => (x * 100 >> 0) % 10 === 0 && (x * 100 >> 0) !== p
                && console.log(`Scrypt progress: ${p = x * 100 >> 0}%`),
        },
    );

    if (!(scryptOutput instanceof Uint8Array) || scryptOutput.length !== outputLength) {
        throw new Error(`Scrypt output is expected to be ${outputLength}-byte Uint8Array.`);
    }

    return scryptOutput; // Uint8Array
}



