
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

const hasHexBuiltin = (() => typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function")();
const asciis = { _0: 48, _9: 57, A: 65, F: 70, a: 97, f: 102 };
function asciiToBase16(ch) {
    if (ch >= asciis._0 && ch <= asciis._9)
        return ch - asciis._0;
    if (ch >= asciis.A && ch <= asciis.F)
        return ch - (asciis.A - 10);
    if (ch >= asciis.a && ch <= asciis.f)
        return ch - (asciis.a - 10);
    return;
}
export function hexToBytes(hex) {
    if (typeof hex !== "string") throw new Error(`hex string expected, got ${typeof hex}`);
    if (hasHexBuiltin) return Uint8Array.fromHex(hex);

    const hl = hex.length;
    const al = hl / 2;

    if (hl % 2) throw new Error(`hex string expected, got unpadded hex of length ${hl}`);
    const array = new Uint8Array(al);

    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
        const n1 = asciiToBase16(hex.charCodeAt(hi));
        const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
        if (n1 === undefined || n2 === undefined) {
            const char = hex[hi] + hex[hi + 1];
            throw new Error(`hex string expected, got non-hex character "${char}" at index ${hi}`);
        }
        array[ai] = n1 * 16 + n2;
    }
    return array;
}
const hexes = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
export function bytesToHex(bytes) {
    if (!(bytes instanceof Uint8Array)) throw new Error("bytesToHex expects Uint8Array input");

    if (hasHexBuiltin) return bytes.toHex();

    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
        hex += hexes[bytes[i]];
    }
    return hex;
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

export function shuffleArr(
    array,
) {
    for (let i = array.length - 1; i > 0; i--) {
        const j = randomBytes(1)[0] % (i + 1);
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}

export function cmpAscii(a, b) {
    const len = Math.min(a.length, b.length);
    for (let i = 0; i < len; i++) {
        const diff = a.codePointAt(i) - b.codePointAt(i);
        if (diff !== 0) return diff;
    }
    return a.length - b.length;
}

export function sortObjKeys(value) {
    if (Array.isArray(value)) {
        return value.map(sortObjKeys);
    }

    if (value && typeof value === "object" && value.constructor === Object) {
        const result = Object.create(null);
        Object.keys(value)
            .sort(cmpAscii)
            .forEach(key => {
                result[key] = sortObjKeys(value[key]);
            });
        return result;
    }

    return value;
}

export function stripOuterQuotes(str) {
    if (typeof str !== "string") {
        throw new TypeError("Expected string");
    }

    let start = 0;
    let end = str.length;

    while (start < end && str[start] === '"') start++;
    while (end > start && str[end - 1] === '"') end--;

    return str.slice(start, end);
}

export function buildPatternArr(pattern, times) {
    const plen = pattern.length;
    const result = new Array(plen * times);

    let offset = 0;
    for (let i = 0; i < times; i++) {
        for (let j = 0; j < plen; j++) {
            result[offset++] = pattern[j];
        }
    }

    return result;
}
