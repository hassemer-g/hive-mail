import {
    Client,
} from "@hiveio/dhive";

import { shuffleArray } from "../[LIB]/shuffle_array.js";
import {
    validatePubPQkey,
} from "../[LIB]/pq.js";

import {
    validateHivePubKey,
} from "./sync_aux_fxs.js";


// ==================================================================== //


// Function to fetch the opIndex of the most recent operation in an account's history
export async function fetchLatestOpIndex(
    accountName,
    RPCs, // array of strings
) {

    try {
        // Fetch info on the latest operation in the account's history
        const history = await new Client(shuffleArray(RPCs)).call("condenser_api", "get_account_history", [accountName, -1, 1]);

        if (!history.length) {
            console.log(`No transactions found for account ${accountName}.`);
            throw new Error(`No transactions found for account ${accountName}.`);
        }

        const [opIndex] = history[0]; // The first element contains the opIndex
        console.log(`Latest operation index for account ${accountName}: ${opIndex}`);
        return opIndex;

    } catch (err) {
        console.error(`Error fetching latest operation index for account ${accountName}: ${err}`);
        throw err;
    }
}


// Fetch current public memo and PQ keys of a Hive account
export async function fetchCurrentPubKeys(
    accountName,
    RPCs, // flat array of strings
    fetchOnlyMemoKey = false,
) {

    try {

        const [accountData] = await new Client(shuffleArray(RPCs)).database.getAccounts([accountName]);

        if (
            !accountData
            || typeof accountData !== "object"
            || Array.isArray(accountData)
            || typeof accountData.memo_key !== "string"
            || !validateHivePubKey(accountData.memo_key)
        ) {
            throw new Error(`Account "${accountName}" not found, or invalid data retrieved.`);
        }

        console.log(`Current public memo key for account ${accountName}: ${accountData.memo_key}`);

        if (fetchOnlyMemoKey) {
            return {
                pubMemoKey: accountData.memo_key,
                // pubPQkey: null,
            };
        }

        // Parse posting metadata
        let postingMetadata = null;
        try {
            postingMetadata = JSON.parse(accountData.posting_json_metadata);
        } catch (err) {
            // Invalid JSON, ensure null
            postingMetadata = null;
        }

        // Check whether the account has a public PQ key registered in its posting metadata
        const hasPQkey = (
            postingMetadata
            && typeof postingMetadata === "object"
            && !Array.isArray(postingMetadata)
            && postingMetadata?.["ჰ0"]
            && typeof postingMetadata?.["ჰ0"] === "object"
            && !Array.isArray(postingMetadata?.["ჰ0"])
            && validatePubPQkey(postingMetadata?.["ჰ0"]?.["ქ"])
        );

        if (hasPQkey) {
            console.log(`
    Current Public Post-Quantum Key for account ${accountName}:
    ${postingMetadata["ჰ0"]["ქ"]}
            `);

            return {
                pubMemoKey: accountData.memo_key,
                pubPQkey: postingMetadata["ჰ0"]["ქ"],
            };

        } else {
            throw new Error(`Account ${accountName} does not have valid special public keys registered.`);
        }

    } catch (err) {
        console.error(`Failed to fetch current public keys for account ${accountName}. Error: ${err.message}`);
        throw err;
    }
}


// Check onchain whether the provided Hive keys are correct
export async function testHiveKeys(
    accountName,
    pubPostingKey, // string
    pubMemoKey, // string
    RPCs, // flat array of strings
) {

    try {

        if (
            typeof pubPostingKey !== "string"
            || !validateHivePubKey(pubPostingKey)
            || typeof pubMemoKey !== "string"
            || !validateHivePubKey(pubMemoKey)
        ) {
            console.error(`Invalid public key inputs!`);
            return false;
        }

        // Get account data onchain
        const [accountData] = await new Client(shuffleArray(RPCs)).database.getAccounts([accountName]);

        if (
            !accountData
            || typeof accountData !== "object"
            || Array.isArray(accountData)
            || typeof accountData.posting?.key_auths?.[0]?.[0] !== "string"
            || !validateHivePubKey(accountData.posting?.key_auths?.[0]?.[0])
            || typeof accountData.memo_key !== "string"
            || !validateHivePubKey(accountData.memo_key)
        ) {
            console.error(`Account "${accountName}" not found, or invalid data retrieved.`);
            return false;
        }

        /*
        // Debugging
        console.log("Account data retrieved:", accountData);
        */

        if (accountData.posting?.key_auths?.[0]?.[1] < accountData.posting?.weight_threshold) {
            console.error(`Unsuitable Posting Authority for account ${accountName}.`);
            return false;
        }

        return accountData.posting?.key_auths?.[0]?.[0] === pubPostingKey
            && accountData.memo_key === pubMemoKey;

    } catch (err) {
        console.error(`Failed to fetch onchain data for account ${accountName}. Error: ${err.message}`);
        return false;
    }
}


// Get onchain the op index of the oldest custom_json op of a single 1000 ops batch
async function getCJbatchOldestOpIndex(
    accountName,
    RPCs, // flat array of strings
) {

    try {

        const limit = 1000;
        const start = -1;

        // Bitmask filters: "custom_json" is operation 18 (bit 18 in operation_filter_low)
        const opFilterLow = (1 << 18);  // Sets only bit 18 ("custom_json")
        const opFilterHigh = 0;         // No high operations are filtered

        const history = await new Client(shuffleArray(RPCs)).call("condenser_api", "get_account_history", [
            accountName,
            start,
            limit,
            opFilterLow,
            opFilterHigh,
        ]);

        if (!history || !Array.isArray(history) || history.length === 0) {
            throw new Error(`No history found for account ${accountName}.`);
        }

        /*
        // Debugging
        console.log(history);
        */

        // Get the lowest operation index of this history batch
        let lowestOpIndex = null;
        for (const [opIndex, _] of history) {

            if (lowestOpIndex === null || opIndex < lowestOpIndex) {
                lowestOpIndex = opIndex;
            }
        }

        /*
        // Debugging
        console.log(`Lowest operation index of this history batch: ${lowestOpIndex}.`);
        */

        return lowestOpIndex;
    } catch (err) {
        console.error(`Failed to fetch onchain data for account ${accountName}. Error: ${err.message}`);
        throw err;
    }
}


// Test user-provided "highest op seen"
export async function testOpIndexSeen(
    account,
    inputOpIndex, // string, can be empty
    RPCs, // flat array of strings
) {

    try {

        let testedOpIndex = 0;

        if (inputOpIndex === "") {

            try {
                const retrievedOpIndex = await getCJbatchOldestOpIndex(
                    account,
                    RPCs, // flat array of strings
                );
                testedOpIndex = retrievedOpIndex;

            } catch (err) {
                testedOpIndex = 0;
            }

        } else if (inputOpIndex && inputOpIndex !== "0") {
            const inputOpIndexInt = parseInt(inputOpIndex);

            if (!Number.isInteger(inputOpIndexInt)) {
                throw new Error(`Invalid operation index input.`);
            }

            // Fetch onchain this account's highest op index
            const accountHighestOpIndex = await fetchLatestOpIndex(
                account,
                RPCs, // flat array of strings
            );

            // Ensure the user-provided index is ok
            testedOpIndex = inputOpIndexInt <= accountHighestOpIndex && inputOpIndexInt > 0 ? inputOpIndexInt : accountHighestOpIndex;
        }

        return testedOpIndex || 0;
    } catch (err) {
        throw err;
    }
}










