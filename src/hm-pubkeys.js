import {
    encBase87,
    decBase87,
} from "./base87.js";
import { valStringCharSet } from "./val.js";
import {
    base87CharSet,
} from "./charsets.js";
import {
    callHiveNode,
} from "./rpcs.js";
import {
    valHMpubKey,
} from "./hm-keys.js";

export async function fetchPubKey(
    accName,
    nodes = null,
) {
    const [accData] = await callHiveNode(
        "get_accounts",
        [accName],
        nodes,
    );

    if (
        !accData?.json_metadata
    ) { throw new Error(`Account "${accName}" not found, or invalid data retrieved`); }

    let metadata;
    try {
        metadata = JSON.parse(accData.json_metadata);
    } catch (err) {
        throw new Error(`Invalid data retrieved for account "${accName}"`);
    }

    if (
        metadata?.["ჰM"]?.[0] === 2
        && valStringCharSet(metadata?.["ჰM"]?.[1], base87CharSet)
        && valHMpubKey(decBase87(metadata?.["ჰM"]?.[1]))
    ) {
        return [decBase87(metadata["ჰM"][1]), metadata];
    } else {
        console.warn(`
    Account "${accName}" does not have the required Hive-Mail public key registered.
`);
        return [null, metadata];
    }
}

export async function checkPubKey(
    accName,
    pubHMkey,
    metadata,
) {
    const stringPubHMkey = encBase87(pubHMkey);

    let updateNeeded = false;
    if (
        !metadata
        || typeof metadata !== "object"
        || Array.isArray(metadata)
    ) {
        metadata = {};
        metadata["ჰM"] = [2, stringPubHMkey];
        updateNeeded = true;
    }

    if (
        !updateNeeded
        && (
            !Array.isArray(metadata["ჰM"])
            || metadata["ჰM"].length !== 2
        )
    ) {
        metadata["ჰM"] = [2, stringPubHMkey];
        updateNeeded = true;
    }

    if (
        !updateNeeded
        && metadata["ჰM"][0] !== 2
    ) {
        metadata["ჰM"] = [2, stringPubHMkey];
        updateNeeded = true;
    }

    if (
        !updateNeeded
        && metadata["ჰM"][1] !== stringPubHMkey
    ) {
        metadata["ჰM"] = [2, stringPubHMkey];
        updateNeeded = true;
    }

    if (updateNeeded) {
        return [
            [
                "account_update2",
                {
                    account: accName,
                    extensions: [],
                    json_metadata: JSON.stringify(metadata),
                    posting_json_metadata: "",
                },
            ],
        ];

    } else {
        console.log(`
    No updates needed for the Hive-Mail Public Key registered in the onchain metadata of account "${accName}"
`);
        return false;
    }
}

export async function checkForRemoval(
    accName,
    nodes = null,
) {
    const [accData] = await callHiveNode(
        "get_accounts",
        [accName],
        nodes,
    );

    if (
        !accData?.json_metadata
    ) {
        console.error(`Account "${accName}" not found, or invalid data retrieved`);
        return [false, null];
    }

    let metadata;
    try {
        metadata = JSON.parse(accData.json_metadata);
    } catch (err) {
        console.error(`Failed to parse metadata retrieved from account "${accName}"`);
        return [false, null];
    }

    if (
        !metadata
        || typeof metadata !== "object"
        || Array.isArray(metadata)
    ) { return [false, null]; }

    if (Object.keys(metadata).some(k => /^ჰM\d*$/.test(k))) {
        return [true, metadata];
    } else {
        return [false, null];
    }
}

export async function removeHMitems(
    accName,
    metadata,

) {
    for (const key of Object.keys(metadata)) {
        if (/^ჰM\d*$/.test(key)) delete metadata[key];
    }

    return [
        [
            "account_update2",
            {
                account: accName,
                extensions: [],
                json_metadata: JSON.stringify(metadata),
                posting_json_metadata: "",
            },
        ],
    ];
}
