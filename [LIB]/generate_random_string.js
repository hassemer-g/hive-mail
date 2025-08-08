import {
    randomBytes,
} from "@noble/hashes/utils";

import { shuffleString } from "./shuffle_string.js";


// ==================================================================== //


// Generate a cryptographically strong random string
export function generateRandomString(
    stringLength,
    charSet, // string
) {

    let result = "";

    const shuffledCharSet = shuffleString(charSet);
    const randomB = randomBytes(stringLength);

    for (let i = 0; i < stringLength; i++) {
        const index = randomB[i] % shuffledCharSet.length;
        result += shuffledCharSet[index];
    }

    return result;
}


