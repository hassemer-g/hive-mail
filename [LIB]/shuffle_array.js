import {
    randomBytes,
} from "@noble/hashes/utils";


// ==================================================================== //


// Shuffle items inside an array
export function shuffleArray(
    array,
) {

    // Fisher-Yates shuffle
    for (let i = array.length - 1; i > 0; i--) {
        const j = randomBytes(1)[0] % (i + 1);
        [array[i], array[j]] = [array[j], array[i]];
    }

    return array;
}




