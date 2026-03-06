
export function createBase(alphabet) {
    if (alphabet.length < 2) {
        throw new TypeError(`Alphabet too short`);
    }
    if (alphabet.length > 254) {
        throw new TypeError(`Alphabet too long`);
    }

    const BASE_MAP = new Uint8Array(256).fill(255);
    for (let i = 0; i < alphabet.length; i++) {
        const c = alphabet.charCodeAt(i);
        if (BASE_MAP[c] !== 255) {
            throw new TypeError(alphabet[i] + ` is ambiguous`);
        }
        BASE_MAP[c] = i;
    }

    const BASE = alphabet.length;
    const LEADER = alphabet[0];
    const FACTOR = Math.log(BASE) / Math.log(256);
    const iFACTOR = Math.log(256) / Math.log(BASE);

    function encode(source) {
        if (!(source instanceof Uint8Array)) {
            throw new TypeError(`Expected Uint8Array`);
        }
        const srcLen = source.length;
        if (srcLen === 0) return "";

        let zeroes = 0;
        let p = 0;
        while (p < srcLen && source[p] === 0) {
            zeroes++;
            p++;
        }

        const size = ((srcLen - p) * iFACTOR + 1) >>> 0;
        const bs = new Uint8Array(size);
        let length = 0;

        while (p < srcLen) {
            let carry = source[p];
            let i = 0;

            for (let j = size - 1; (carry !== 0 || i < length) && j >= 0; j--, i++) {
                carry += 256 * bs[j];
                bs[j] = carry % BASE;
                carry = (carry / BASE) | 0;
            }

            if (carry !== 0) throw new Error(`Non-zero carry`);
            length = i;
            p++;
        }

        let it = size - length;
        while (it < size && bs[it] === 0) it++;

        const outLen = zeroes + (size - it);
        const chars = new Array(outLen);

        chars.fill(LEADER, 0, zeroes);

        let k = zeroes;
        while (it < size) {
            chars[k++] = alphabet[bs[it++]];
        }

        return chars.join("");
    }

    function decode(source) {
        if (typeof source !== "string") {
            throw new TypeError(`Expected string`);
        }
        if (source.length === 0) return new Uint8Array();

        let zeroes = 0;
        let p = 0;
        while (source[p] === LEADER) {
            zeroes++;
            p++;
        }

        const size = (((source.length - p) * FACTOR) + 1) >>> 0;
        const b256 = new Uint8Array(size);
        let length = 0;

        while (p < source.length) {
            const c = source.charCodeAt(p);
            if (c > 255) throw new Error(`Invalid character`);

            let carry = BASE_MAP[c];
            if (carry === 255) throw new Error(`Invalid character`);

            let i = 0;
            for (let j = size - 1; (carry !== 0 || i < length) && j >= 0; j--, i++) {
                carry += BASE * b256[j];
                b256[j] = carry % 256;
                carry = (carry / 256) | 0;
            }
            if (carry !== 0) throw new Error(`Non-zero carry`);
            length = i;
            p++;
        }

        let it = size - length;
        while (it < size && b256[it] === 0) it++;

        const out = new Uint8Array(zeroes + (size - it));
        out.fill(0, 0, zeroes);
        let j = zeroes;
        while (it < size) {
            out[j++] = b256[it++];
        }
        return out;
    }

    return [encode, decode];
}
