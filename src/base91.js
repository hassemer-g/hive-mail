import {
    customBase91CharSet,
} from "./charsets.js";
import { valStringCharSet } from "./val.js";

export function encodeBase91(
    data,
) {

    if (!(data instanceof Uint8Array)) {
        throw new Error(`Input to the "encodeBase91" function should be a Uint8Array.`);
    }

    const len = data.length;
    let ret = "";

    let n = 0;
    let b = 0;

    for (let i = 0; i < len; i++) {
        b |= data[i] << n;
        n += 8;

        if (n > 13) {
            let v = b & 8191;

            if (v > 88) {
                b >>= 13;
                n -= 13;

            } else {
                v = b & 16383;
                b >>= 14;
                n -= 14;
            }

            ret += customBase91CharSet[v % 91] + customBase91CharSet[v / 91 | 0];
        }
    }

    if (n) {
        ret += customBase91CharSet[b % 91];

        if (n > 7 || b > 90) ret += customBase91CharSet[b / 91 | 0];
    }

    return ret;
}

export function decodeBase91(
    data,
) {

    if (
        typeof data !== "string"
        || !valStringCharSet(data, customBase91CharSet)
    ) {
        throw new Error(`Input to the "decodeBase91" function should be a Base91-encoded string.`);
    }

    const len = data.length;
    const ret = [];

    let b = 0;
    let n = 0;
    let v = -1;

    for (let i = 0; i < len; i++) {
        const p = customBase91CharSet.indexOf(data[i]);

        if (p === -1) continue;

        if (v < 0) {
            v = p;

        } else {
            v += p * 91;
            b |= v << n;
            n += (v & 8191) > 88 ? 13 : 14;

            do {
                ret.push(b & 0xff);
                b >>= 8;
                n -= 8;
            } while (n > 7);

            v = -1;
        }
    }

    if (v > -1) {
        ret.push((b | v << n) & 0xff);
    }

    return new Uint8Array(ret);
}
