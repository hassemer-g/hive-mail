import {
    randomBytes,
} from "@noble/hashes/utils";


// ==================================================================== //


// Shuffle string
export function shuffleString(
    string,
) {

    const array = [...string];

    // Fisher-Yates shuffle
    for (let i = array.length - 1; i > 0; i--) {
        const j = randomBytes(1)[0] % (i + 1);
        [array[i], array[j]] = [array[j], array[i]];
    }

    return array.join("");
}




