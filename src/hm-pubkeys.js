import dhive from "./dhive/dhive.mjs";

import {
    encodeBase91,
    decodeBase91,
} from "./base91.js";
import {
    shuffleArray,
} from "./utils.js";
import { valStringCharSet } from "./val.js";
import {
    customBase91CharSet,
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

        const stringPubHMkey = encodeBase91(pubHMkey);

        const [accountData] = await new dhive.Client(shuffleArray(RPCs)).database.getAccounts([accountName]);

        if (!accountData) {
            throw new Error(`Account "${accountName}" not found.`);
        }

        let metadata = {};
        let invalidMetadata = false;

        if (!accountData.json_metadata) {
            metadata["ჰM0"] = "";
            invalidMetadata = true;
        }

        if (!invalidMetadata) {
            try {
                metadata = JSON.parse(accountData.json_metadata);

            } catch (err) {
                metadata = {};
                metadata["ჰM0"] = "";
                invalidMetadata = true;
            }
        }

        if (
            !invalidMetadata &&
            (!metadata || typeof metadata !== "object" || Array.isArray(metadata))
        ) {
            metadata = {};
            metadata["ჰM0"] = "";
            invalidMetadata = true;
        }

        if (
            !invalidMetadata &&
            (typeof metadata["ჰM0"] !== "string")
        ) {
            metadata["ჰM0"] = "";
            invalidMetadata = true;
        }

        let updateNeeded = false;

        if (metadata["ჰM0"] !== stringPubHMkey) {
            metadata["ჰM0"] = stringPubHMkey;
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
        ) {
            throw new Error(`Account "${accountName}" not found, or invalid data retrieved.`);
        }

        let metadata = null;
        try {
            metadata = JSON.parse(accountData.json_metadata);
        } catch (err) {

            metadata = null;
        }

        const hasKeys = (
            metadata
            && typeof metadata === "object"
            && !Array.isArray(metadata)
            && valStringCharSet(metadata?.["ჰM0"], customBase91CharSet)
            && valHMpubKey(decodeBase91(metadata?.["ჰM0"]))
        );

        if (hasKeys) {
            return decodeBase91(metadata["ჰM0"]);

        } else {
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

    if (!accountData) {
        console.error(`Account "${accountName}" not found.`);
        return false;
    }

    let metadata = {};
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
    ) {
        return false;
    }

    if (Object.keys(metadata).some(k => /^ჰM\d+$/.test(k))) {
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

    if (!accountData) {
        throw new Error(`Account "${accountName}" not found.`);
    }

    let metadata = {};
    try {
        metadata = JSON.parse(accountData.json_metadata);
    } catch (err) {
        throw new Error(`Failed to parse metadata retrieved from account ${accountName}`);
    }

    if (
        !metadata
        || typeof metadata !== "object"
        || Array.isArray(metadata)
    ) {
        throw new Error(`The metadata retrieved from account ${accountName} is not an object!`);
    }

    for (const key of Object.keys(metadata)) {
        if (/^ჰM\d+$/.test(key)) delete metadata[key];
    }

    return metadata;
}
