import {
    customBase91CharSet,
} from "./charsets.js";

export function encodeBase91(
    d,
) {
    const c = customBase91CharSet;
    const l = d.length;
    let R = "", b = 0, n = 0;

    for (let i = 0; i < l; i++) {
        b |= d[i] << n;
        n += 8;

        if (n >= 14) {
            let v = b & 8191;

            if (v > 88) {
                b >>= 13;
                n -= 13;
            } else {
                v = b & 16383;
                b >>= 14;
                n -= 14;
            }

            const o = v % 91;
            R += c[o] + c[(v - o) / 91];
        }
    }

    if (n) {
        R += c[b % 91];

        if (n > 7 || b > 90) {
            R += c[(b - (b % 91)) / 91];
        }
    }

    return R;
}

export function decodeBase91(
    d,
) {
    const c = customBase91CharSet;
    const l = d.length;
    const R = [];
    let o = 0, b = 0, n = 0, v = -1;

    const r = new Int16Array(256);
    r.fill(-1);
    for (let i = 0; i < 91; i++) {
        r[c.charCodeAt(i)] = i;
    }

    for (let i = 0; i < l; i++) {
        const p = r[d.charCodeAt(i)];
        if (p === -1) continue;

        if (v < 0) {
            v = p;
        } else {
            v += p * 91;
            b |= v << n;
            n += (v & 8191) > 88 ? 13 : 14;

            while (n >= 8) {
                R[o++] = b & 0xff;
                b >>= 8;
                n -= 8;
            }

            v = -1;
        }
    }

    if (v > -1) {
        R[o++] = (b | (v << n)) & 0xff;
    }

    return new Uint8Array(R);
}
