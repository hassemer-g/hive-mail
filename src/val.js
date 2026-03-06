
export function valStringCharSet(
    input,
    charSet,
) {
    if (
        typeof input !== "string"
        || !input.trim()
        || typeof charSet !== "string"
        || !charSet.trim()
    ) { return false; }

    const allowed = new Set(charSet);

    const len = input.length;
    for (let i = 0; i < len; i++) {
        if (!allowed.has(input[i])) { return false; }
    }

    return true;
}
