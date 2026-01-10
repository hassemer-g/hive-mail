
export function concatUint8Arr(...arrays) {
    if (arrays.length === 0) return new Uint8Array(0);

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

export function wipeUint8Arr() {
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
