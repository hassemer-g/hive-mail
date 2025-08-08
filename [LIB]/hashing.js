import { blake2b } from "@noble/hashes/blake2";
import { sha3_512 } from "@noble/hashes/sha3";
import {
    utf8ToBytes,
} from "@noble/hashes/utils";


// ==================================================================== //


// Perform standard hashing routine
export function doHashing(
    input, // Uint8Array, non-empty string, integer, object or array
) {

    // Ensure Uint8Array input (required for the hashing functions)
    if (input instanceof Uint8Array) {
        // do nothing
    } else if (typeof input === "string" && input.trim() !== "") {
        input = utf8ToBytes(input);
    } else if (Number.isInteger(input)) {
        input = utf8ToBytes(String(input));
    } else if (input && typeof input === "object") { // already includes arrays
        input = utf8ToBytes(JSON.stringify(input, null, 0));
    } else {
        throw new Error(`Invalid input! Acceptable input types for "doHashing": Uint8Array, non-empty string, integer, object or array.`);
    }

    const blake2bOutput = blake2b(input);  // Receives and returns Uint8Array (64-byte output by default)

    if (!(blake2bOutput instanceof Uint8Array) || blake2bOutput.length !== 64) {
        throw new Error("Blake2b output is expected to be 64-byte Uint8Array.");
    }

    const sha3Output = sha3_512(blake2bOutput); // Receives and returns Uint8Array

    if (!(sha3Output instanceof Uint8Array) || sha3Output.length !== 64) {
        throw new Error("SHA3-512 output is expected to be 64-byte Uint8Array.");
    }

    return sha3Output; // Uint8Array

}



