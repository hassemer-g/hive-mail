
const HAS_BUFFER = typeof Buffer === "function";

export function encodeBase64(
    data,
    outUrlSafe = false,
    outNotPadded = false,
) {
    let b64 = HAS_BUFFER
        ? Buffer.from(data).toString("base64")
        : (() => {

            const len = data.length;
            let bin = "";
            for (let i = 0; i < len; i++) {
                bin += String.fromCharCode(data[i]);
            }
            return btoa(bin);
        })();

    if (outUrlSafe) {
        return b64.replace(/[=+/]/g, (c) => (c === "=" ? "" : c === "+" ? "-" : "_"));
    }

    if (outNotPadded) {
        return b64.replace(/=+$/, "");
    }

    return b64;
}

export function decodeBase64(
    data,
) {
    const cleaned = data.replace(/[-_]/g, (c) => (c === "-" ? "+" : "/")).replace(/[^A-Za-z0-9+/]/g, "");

    if (HAS_BUFFER) {
        return Uint8Array.from(
            Buffer.from(cleaned, "base64")
        );
    }

    const bin = atob(cleaned);
    const len = bin.length;
    const out = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        out[i] = bin.charCodeAt(i);
    }
    return out;
}
