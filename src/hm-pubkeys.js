import dhive from "./dhive/dhive.mjs";
import {
    encodeBase64,
    decodeBase64,
} from "./base64.js";
import {
    shuffleArray,
} from "./utils.js";
import { valStringCharSet } from "./val.js";
import {
    urlSafeBase64CharSet,
} from "./charsets.js";
import {
    valHMpubKey,
} from "./hm-keys.js";

export async function checkPubKeyOnchain(
    accountName,
    pubHMkey,
    RPCs,
) {
    try {
        const [accountData] = await new dhive.Client(shuffleArray(RPCs)).database.getAccounts([accountName]);
        if (
            !accountData
            || typeof accountData !== "object"
            || Array.isArray(accountData)
        ) { throw new Error(`Account "${accountName}" not found, or invalid data retrieved.`); }

        const stringPubHMkey = encodeBase64(pubHMkey, true);
        let metadata = {}, updateNeeded = false;
        if (!accountData.json_metadata) {
            metadata["ჰM"] = [1, stringPubHMkey];
            updateNeeded = true;
        }

        if (!updateNeeded) {
            try {
                metadata = JSON.parse(accountData.json_metadata);
            } catch (err) {
                metadata = {};
                metadata["ჰM"] = [1, stringPubHMkey];
                updateNeeded = true;
            }
        }

        if (
            !updateNeeded
            && (!metadata || typeof metadata !== "object" || Array.isArray(metadata))
        ) {
            metadata = {};
            metadata["ჰM"] = [1, stringPubHMkey];
            updateNeeded = true;
        }

        if (
            !updateNeeded
            && (!Array.isArray(metadata["ჰM"]) || metadata["ჰM"].length !== 2)
        ) {
            metadata["ჰM"] = [1, stringPubHMkey];
            updateNeeded = true;
        }

        if (
            !updateNeeded
            && metadata["ჰM"][0] !== 1
        ) {
            metadata["ჰM"] = [1, stringPubHMkey];
            updateNeeded = true;
        }

        if (
            !updateNeeded
            && metadata["ჰM"][1] !== stringPubHMkey
        ) {
            metadata["ჰM"] = [1, stringPubHMkey];
            updateNeeded = true;
        }

        if (updateNeeded) {
            return metadata;

        } else {
            console.log(`
    No updates needed for your Hive-Mail public key in your account's onchain Metadata.
            `);
            return null;
        }

    } catch (err) {
        console.error(`
    Failed to check the Hive-Mail public key for account ${accountName}.
    Error: ${err.message}
        `);
        throw err;
    }
}

export async function fetchPubKey(
    accountName,
    RPCs,
) {
    try {
        const [accountData] = await new dhive.Client(shuffleArray(RPCs)).database.getAccounts([accountName]);
        if (
            !accountData
            || typeof accountData !== "object"
            || Array.isArray(accountData)
        ) { throw new Error(`Account "${accountName}" not found, or invalid data retrieved.`); }

        let metadata;
        try {
            metadata = JSON.parse(accountData.json_metadata);
        } catch (err) {
            metadata = null;
        }

        if (
            metadata
            && typeof metadata === "object"
            && !Array.isArray(metadata)
            && metadata?.["ჰM"]?.[0] === 1
            && valStringCharSet(metadata?.["ჰM"]?.[1], urlSafeBase64CharSet)
            && valHMpubKey(decodeBase64(metadata?.["ჰM"]?.[1]))
        ) { return decodeBase64(metadata["ჰM"][1]); }
        else {
            console.warn(`
    Account ${accountName} does not have the required Hive-Mail public key registered.
            `);
            return null;
        }

    } catch (err) {
        console.error(`
    Failed to fetch the current Hive-Mail public key for account ${accountName}.
    Error: ${err.message}
        `);
        throw err;
    }
}

export async function checkForRemoval(
    accountName,
    RPCs,
) {
    const [accountData] = await new dhive.Client(shuffleArray(RPCs)).database.getAccounts([accountName]);
    if (
        !accountData
        || typeof accountData !== "object"
        || Array.isArray(accountData)
    ) {
        console.error(`Account "${accountName}" not found, or invalid data retrieved.`);
        return false;
    }

    let metadata;
    try {
        metadata = JSON.parse(accountData.json_metadata);
    } catch (err) {
        console.error(`Failed to parse metadata retrieved from account ${accountName}`);
        return false;
    }

    if (
        !metadata
        || typeof metadata !== "object"
        || Array.isArray(metadata)
    ) { return false; }

    if (Object.keys(metadata).some(k => /^ჰM\d*$/.test(k))) {
        return true;
    } else {
        return false;
    }
}

export async function removeHMitems(
    accountName,
    RPCs,
) {
    const [accountData] = await new dhive.Client(shuffleArray(RPCs)).database.getAccounts([accountName]);
    if (
        !accountData
        || typeof accountData !== "object"
        || Array.isArray(accountData)
    ) { throw new Error(`Account "${accountName}" not found, or invalid data retrieved.`); }

    let metadata;
    try {
        metadata = JSON.parse(accountData.json_metadata);
    } catch (err) {
        throw new Error(`Failed to parse metadata retrieved from account ${accountName}`);
    }

    if (
        !metadata
        || typeof metadata !== "object"
        || Array.isArray(metadata)
    ) { throw new Error(`The metadata retrieved from account ${accountName} is not an object!`); }

    for (const key of Object.keys(metadata)) {
        if (/^ჰM\d*$/.test(key)) delete metadata[key];
    }

    return metadata;
}
