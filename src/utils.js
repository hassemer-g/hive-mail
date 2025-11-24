
export function concatBytes(...arrays) {
    let totalLength = 0;
    for (let i = 0; i < arrays.length; i++) {
        const a = arrays[i];
        totalLength += a.length;
    }

    const result = new Uint8Array(totalLength);
    for (let i = 0, offset = 0; i < arrays.length; i++) {
        const a = arrays[i];
        result.set(a, offset);
        offset += a.length;
    }

    return result;
}

export function compareUint8arrays(a, b) {
    const lenA = a.length;
    const lenB = b.length;
    const minLen = lenA < lenB ? lenA : lenB;

    for (let i = 0; i < minLen; i++) {
        const diff = a[i] - b[i];
        if (diff !== 0) return diff;
    }

    return lenA - lenB;
}

export function wipeUint8() {
    for (let i = 0; i < arguments.length; i++) {
        arguments[i].fill(0);
    }
}

export function utf8ToBytes(str) {
    return new Uint8Array(new TextEncoder().encode(str));
}
export function bytesToUtf8(bytes) {
    return new TextDecoder().decode(bytes);
}

export function randomBytes(bytesLength) {

    if (typeof globalThis.crypto?.getRandomValues === "function") {
        return globalThis.crypto.getRandomValues(new Uint8Array(bytesLength));
    }

    if (crypto && typeof crypto.randomBytes === "function") {
        return Uint8Array.from(crypto.randomBytes(bytesLength));
    }

    throw new Error("No cryptographically secure random source available.");
}

export function shuffleArray(
    array,
) {

    for (let i = array.length - 1; i > 0; i--) {
        const j = randomBytes(1)[0] % (i + 1);
        [array[i], array[j]] = [array[j], array[i]];
    }

    return array;
}
