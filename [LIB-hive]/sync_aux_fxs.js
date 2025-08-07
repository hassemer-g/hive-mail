

// ==================================================================== //


// Validate Hive account name structure
export function validateAccountNameStructure(accountName) {
    const accountNameRegex = /^[a-z](([a-z0-9-]+)?[a-z0-9])?(\.[a-z](([a-z0-9-]+)?[a-z0-9])?)*$/;

    // Check if dots are correctly positioned (at least 3 non-dot characters before & after each dot)
    const validDotPlacement = !accountName.includes(".") || accountName.split(".").every(part => part.length >= 3);

    // Ensure a dot is NOT immediately followed by a hyphen or a number
    const noDotFollowedByHyphenOrNumber = !/\.[0-9-]/.test(accountName);

    return (
        accountName.length >= 3
        && accountName.length <= 16
        && accountNameRegex.test(accountName)
        && validDotPlacement
        && noDotFollowedByHyphenOrNumber
        && !accountName.includes("-.")
    );
}


// Validate Hive private key
export function validateHivePrivKey(privKey) {
    const privKeyRegex = /^5[1-9A-HJ-NP-Za-km-z]{50}$/;
    return privKey.length === 51 && privKeyRegex.test(privKey);
}


// Validate Hive public key
export function validateHivePubKey(pubKey) {
    const pubKeyRegex = /^STM[1-9A-HJ-NP-Za-km-z]{50}$/;
    return pubKey.length === 53 && pubKeyRegex.test(pubKey);
}



