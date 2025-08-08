


// ==================================================================== //


// Check whether all characters in a string are present in a specific character set
export function validateStringCharSet(
    input, // string
    charSet, // string
) {

    if (typeof input !== "string") {
        throw new Error(`Input of "validateStringCharSet" should be a string!`);
    }

    const allowed = new Set(charSet);

    for (const char of input) {
        if (!allowed.has(char)) {
            return false;
        }
    }

    return true;
}



