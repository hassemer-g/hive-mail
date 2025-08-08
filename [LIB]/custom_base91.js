import base91 from "node-base91";

import { validateStringCharSet } from "./validate_string_charset.js";
import {
    customBase91CharSet,
} from "./charsets.js";


// ==================================================================== //


// Convert Uint8Array to a custom-Base91-encoded string
export function bytesToBase91(
    input, // Uint8Array
) {

    // Ensure input is Uint8Array
    if (!(input instanceof Uint8Array)) {
        throw new Error(`Uint8Array input expected for the "bytesToBase91" function.`);
    }

    return base91.encode(input)
        .replace(/\"/g, "-");

}


// Convert a custom-Base91-encoded string to Uint8Array
export function bytesFromBase91(
    input, // custom-Base91 string
) {

    // Ensure input is a string
    if (typeof input !== "string") {
        throw new Error(`String input expected for the "bytesFromBase91" function.`);
    }

    // Check whether input is custom-Base91 encoded
    if (!validateStringCharSet(input, customBase91CharSet)) {
        throw new Error(`Input is not Base91 encoded!`);
    }

    return base91.decode(
        input
            .replace(/-/g, "\"")
    );

}



