

export function valStringCharSet(
    input,
    charSet,
) {

    if (
        [input, charSet].some(v => typeof v !== "string" || !v.trim())
    ) {

        return false;
    }

    const allowed = new Set(charSet);

    for (const char of input) {
        if (!allowed.has(char)) {
            return false;
        }
    }

    return true;
}
