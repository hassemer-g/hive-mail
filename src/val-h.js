

export function valAccountNameStructure(accountName) {

    if (
        [accountName].some(v => typeof v !== "string" || !v.trim())
    ) {
        return false;
    }

    const accountNameRegex = /^[a-z](([a-z0-9-]+)?[a-z0-9])?(\.[a-z](([a-z0-9-]+)?[a-z0-9])?)*$/;

    const validDotPlacement = !accountName.includes(".") || accountName.split(".").every(part => part.length >= 3);

    const noDotFollowedByHyphenOrNumber = !/\.[0-9-]/.test(accountName);

    return (
        !(accountName.length < 3)
        && !(accountName.length > 16)
        && accountNameRegex.test(accountName)
        && validDotPlacement
        && noDotFollowedByHyphenOrNumber
        && !accountName.includes("-.")
    );
}

export function valHivePrivKey(privKey) {
    const privKeyRegex = /^5[1-9A-HJ-NP-Za-km-z]{50}$/;
    return typeof privKey === "string" && privKey.length === 51 && privKeyRegex.test(privKey);
}
