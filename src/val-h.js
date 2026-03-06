
export function valAccName(accName) {
    return typeof accName === "string"
        && accName.length > 2
        && accName.length < 17
        && /^[a-z](([a-z0-9-]+)?[a-z0-9])?(\.[a-z](([a-z0-9-]+)?[a-z0-9])?)*$/.test(accName)
        && (!accName.includes(".") || accName.split(".").every(p => p.length > 2))
        && !/\.[0-9-]/.test(accName)
        && !accName.includes("-.");
}
