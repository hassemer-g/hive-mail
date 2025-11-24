
export function integerToBytes(input) {

    if (typeof input === "number") {
        input = BigInt(input);
    }

    const bytes = [];
    while (input > 0n) {
        bytes.unshift(Number(input & 0xffn));
        input >>= 8n;
    }

    return new Uint8Array(bytes.length ? bytes : [0]);
}
