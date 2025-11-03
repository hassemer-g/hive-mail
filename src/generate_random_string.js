import {
    randomBytes,
} from "./utils.js";

export function generateUniformlyRandomString(
    stringLength,
    charSet,
) {

    let result = "";

    const charSetLength = charSet.length;

    const maxMultiplier = Math.floor(256 / charSetLength);

    if (!(maxMultiplier > 0)) {
        throw new Error(`Character set for "generateUniformlyRandomString" function should not be longer than 256 characters!`);
    }

    while (result.length < stringLength) {
        const byte = randomBytes(1)[0];

        if (byte < charSetLength * maxMultiplier) {
            result += charSet[byte % charSetLength];
        }
    }

    return result;
}
