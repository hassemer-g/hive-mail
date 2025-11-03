

export function integerToBytes(input) {
    if (typeof input !== "bigint" && typeof input !== "number") {
        throw new Error(`Input to "integerToBytes" must be a number or big integer!`);
    }
    if (typeof input === "number") {
        if (!Number.isSafeInteger(input) || input < 0) {
            throw new Error(`Number input to "integerToBytes" must be a non-negative safe integer!`);
        }
        input = BigInt(input);
    }
    if (input < 0n) {
        throw new Error(`Function "integerToBytes" does not support negative values!`);
    }

    const bytes = [];
    while (input > 0n) {
        bytes.unshift(Number(input & 0xffn));
        input >>= 8n;
    }

    return new Uint8Array(bytes.length ? bytes : [0]);
}

export function bytesToInteger(input) {
    if (!(input instanceof Uint8Array)) {
        throw new Error(`Input to "bytesToInteger" must be a Uint8Array!`);
    }

    let result = 0n;
    for (const byte of input) {
        result = (result << 8n) + BigInt(byte);
    }

    if (result <= BigInt(Number.MAX_SAFE_INTEGER)) {
        return Number(result);
    } else {
        return result;
    }
}
