import bs58 from "bs58";
import pqclean from "pqclean";
import {
    bytesToUtf8,
} from "@noble/hashes/utils";
import {
    Client,
    PrivateKey,
    PublicKey,
} from "@hiveio/dhive";

import {
    customBase91CharSet,
} from "../[LIB]/charsets.js";
import {
    bytesToBase91,
    bytesFromBase91,
} from "../[LIB]/custom_base91.js";
import { shuffleArray } from "../[LIB]/shuffle_array.js";
import { validateStringCharSet } from "../[LIB]/validate_string_charset.js";
import {
    decryptXChaCha20Poly1305,
} from "../[LIB]/xchacha20_poly1305.js";
import {
    extractKyberPublicKey,
} from "../[LIB]/pq.js";

import { derivForMsg } from "./hm_deriv.js";
import {
    fetchLatestOpIndex,
} from "./async_aux_fxs.js";


// ==================================================================== //


/*
 *
 *
 * FETCH AND DECRYPT MESSAGES
 *
 *
 */

// Function to fetch account data and validate senders
async function validateExpectedSenders(
    senders,
    RPCs, // flat array of strings
) {

    try {

        console.log(`Fetching sender accounts' data...`);
        const accounts = await new Client(shuffleArray(RPCs)).database.getAccounts(senders);

        const foundAccounts = accounts
            .filter(account => account)  // Remove accounts that do not exist
            .map(account => account.name);

        const missingAccounts = senders.filter(name => !foundAccounts.includes(name));

        if (missingAccounts.length > 0) {
            console.warn(`Warning: These sender accounts were not found: ${missingAccounts.join(", ")}`);
        }

        return foundAccounts;
    } catch (err) {
        console.error(`Failed to validate senders. Error: ${err.message}`);
        throw err;
    }
}


// Perform decryption of message in a Hive Mail custom_json operation
async function performMessageDecryption(
    recipientName,
    recipientPrivMemoKeys, // array of strings
    recipientPrivPQkeys, // array of strings
    senderName,
    opIndex, // integer
    payload, // string
) {

    try {

        // Build transaction code
        const txCode = `${senderName}—${opIndex}—${recipientName}`;
        console.log(`Unique transaction code:`, txCode);

        // Convert payload to Uint8Array
        const payloadBytes = bytesFromBase91(payload);
        if (payloadBytes.length < 1606) {
            throw new Error("Payload is shorter than minimum possible length.");
        }

        // Extract payload constituents
        const memoEphemeral = "STM" + bs58.encode(payloadBytes.slice(0, 37)); // string
        const memoEphemeralBuf = PublicKey.fromString(memoEphemeral);

        /*
        // Debugging
        console.log("\"memoEphemeral\":", memoEphemeral);
        */

        const pqEphemeral = payloadBytes.slice(37, 1605);
        const ciphertext = payloadBytes.slice(1605);

        /*
        // Debugging
        console.log("\"ciphertext\" (Base91):", bytesToBase91(ciphertext));
        console.log("\"ciphertext\" byte length:", ciphertext.length);
        if (payloadBytes.length !== payloadBytes.slice(0, 37).length + payloadBytes.slice(37, 1605).length + payloadBytes.slice(1605).length) {
            throw new Error("Payload byte length inconsistency 1!");
        }
        if (payloadBytes.length !== 37 + 1568 + bytesFromBase91(bytesToBase91(ciphertext)).length) {
            throw new Error("Payload byte length inconsistency 2!");
        }
        */

        for (const privPQkey of recipientPrivPQkeys) {

            // Derive public PQ key from private PQ key
            const pubPQkey = bytesToBase91(extractKyberPublicKey(bytesFromBase91(privPQkey))); // string

            /*
            // Debugging
            console.log("\"pubPQkey\":", pubPQkey);
            */

            const pqPriv = new pqclean.kem.PrivateKey("ml-kem-1024", bytesFromBase91(privPQkey));
            const pqSharedSecretBuf = await pqPriv.decryptKey(pqEphemeral);

            /*
            // Debugging
            console.log("\"pqSharedSecretBuf\":", pqSharedSecretBuf);
            */

            const pqSharedSecret = new Uint8Array(pqSharedSecretBuf); // 32 bytes

            /*
            // Debugging
            console.log("\"pqSharedSecret\", in Base91:", bytesToBase91(pqSharedSecret));
            console.log("\"pqSharedSecret\" byte length:", pqSharedSecret.length);
            */

            for (const privMemoKey of recipientPrivMemoKeys) {

                // Derive public memo key from private memo key
                const privMemoKeyBuf = PrivateKey.fromString(privMemoKey);

                // Retrieve the Memo shared secret
                const memoSharedSecret = new Uint8Array(privMemoKeyBuf.get_shared_secret(memoEphemeralBuf)); // 64 bytes

                /*
                // Debugging
                console.log("\"memoSharedSecret\", in Base91:", bytesToBase91(memoSharedSecret));
                console.log("\"memoSharedSecret\" byte length:", memoSharedSecret.length);
                */

                // Build and derive required keys, nonces, passwords and salts (returns all in Uint8Array)
                const { keyForEncrypt, nonceForEncrypt } = derivForMsg(
                    txCode, // string
                    privMemoKeyBuf.createPublic().toString().slice(3), // string (removed of the "STM" prefix)
                    pubPQkey, // string
                    memoSharedSecret, // Uint8Array, 64 bytes
                    pqSharedSecret, // Uint8Array, 32 bytes
                );

                // Decrypt XChaCha20-Poly1305 (input in Uint8Array, output in UTF8)
                const decrypted = bytesToUtf8(decryptXChaCha20Poly1305(
                    ciphertext, // Uint8Array
                    keyForEncrypt, // Uint8Array
                    nonceForEncrypt, // Uint8Array
                ));
                console.log("Symmetric decryption output:", decrypted);

                if (typeof decrypted === "string" && decrypted.trim() !== "") {

                    console.log(`
    Success in fully decrypting message from ${senderName} at operation index ${opIndex}. Decrypted message:

${decrypted}
                    `);

                    return decrypted;
                } else {
                    break;
                }
            }
        }

        console.warn(`Decryption failed for message from ${senderName} at operation index ${opIndex}.`);
        return null;

    } catch (err) {
        console.warn(`Decryption failed for message from ${senderName} at operation index ${opIndex}. Error: ${err.message}`);
        return null;
    }
}


// Fetch Mail-related "custom_json" operations for a given account
async function fetchMessagesForAccount(
    RPCs, // flat array of strings
    recipientName,
    recipientPrivMemoKeys, // flat array of strings
    recipientPrivPQkeys, // flat array of strings
    senderName,
    previousOpIndexSeen, // integer
    searchType,
) {

    try {

        console.log(`Fetching "custom_json" operations for ${senderName}; highest operation index already seen: ${previousOpIndexSeen}.`);

        const acquiredMessages = [];

        let history = null;
        let reachedEndOfHistory = false;
        let highestOpIndexSeen = searchType === "full" ? previousOpIndexSeen : null;

        // let firstOpIndexSeen = null; // Variable to store the first operation index seen for this sender
        // let highestOpIndexOfGlobalHistory = -1;
        // let highestOpIndexOfBatchHistory = null;

        // Get effective highest operation index
        let senderHighestOpIndex = -1;
        // let noCJopInTheMostRecentBatch = false;
        if (searchType === "full") {

            senderHighestOpIndex = await fetchLatestOpIndex(
                senderName,
                RPCs, // flat array of strings
            );

            if (!senderHighestOpIndex || !Number.isInteger(senderHighestOpIndex) || senderHighestOpIndex < 0) {
                throw new Error(`Unable to fetch highest operation index for account ${senderName}.`);
            }

            /*
            // If no "custom_json" is found among the most recent 1000 ops, try an alternative route
            if (senderHighestOpIndex < 0) {
                noCJopInTheMostRecentBatch = true;
            }
            */
        }

        const limit = 1000;                                                       // Fetch 1000 operations with each API call (max number)
        let start = searchType === "full" ? limit + previousOpIndexSeen : -1;     // Start with the oldest 1000 operations (starting point = start - limit)

        // Bitmask filters: "custom_json" is operation 18 (bit 18 in operation_filter_low)
        const opFilterLow = (1 << 18);  // Sets only bit 18 ("custom_json")
        const opFilterHigh = 0;         // No high operations are filtered

        do {

            if (searchType === "full") {
                console.log(`Fetching account history for ${senderName} with start = ${start}.`);

                history = await new Client(shuffleArray(RPCs)).call("condenser_api", "get_account_history", [
                    senderName,
                    start,
                    limit,
                    // opFilterLow,
                    // opFilterHigh,
                ]);

            } else {

                history = await new Client(shuffleArray(RPCs)).call("condenser_api", "get_account_history", [
                    senderName,
                    start,
                    limit,
                    opFilterLow,
                    opFilterHigh,
                ]);
            }

            if (!history || !Array.isArray(history) || history.length === 0) {
                console.error(`No history found for account ${senderName}.`);
                break;
            }

            /*
            // Debugging
            console.log(history);
            fs.writeFileSync(`history_${senderName}_${start}.json`, JSON.stringify(history, null, 2), "utf8");
            */

            /*
            if (noCJopInTheMostRecentBatch) {
                highestOpIndexOfBatchHistory = -1;
                for (const [opIndex, _] of history) {

                    // Record the highest operation index in this history batch
                    if (opIndex > highestOpIndexOfBatchHistory) {
                        highestOpIndexOfBatchHistory = opIndex;
                    }
                }

                console.log(`Highest operation index of this history batch: ${highestOpIndexOfBatchHistory}; current global highest: ${highestOpIndexOfGlobalHistory}`);

                if (highestOpIndexOfBatchHistory <= highestOpIndexOfGlobalHistory) {
                    console.log(`Reached the end of history for ${senderName}.`);
                    break;
                    // reachedEndOfHistory = true;

                } else {
                    highestOpIndexOfGlobalHistory = highestOpIndexOfBatchHistory;
                }
            }

            // Exit the do/while loop if reachedEndOfHistory is true
            if (reachedEndOfHistory) break;
            */

            for (const [opIndex, op] of history) {

                // Debugging
                // console.log(`Processing operation from sender ${senderName} at index ${opIndex}, with transaction ID: ${op.trx_id}`);

                /*
                // Check if operation index was already processed, to prevent infinite loop
                if (searchType === "full" && opIndex === firstOpIndexSeen) {
                    console.warn(`Duplicate operation detected, at index ${opIndex}. Reached the end of history for ${senderName}.`);
                    reachedEndOfHistory = true;
                    break;
                }

                // Store the first operation index encountered in this search
                if (searchType === "full" && firstOpIndexSeen === null) {
                    firstOpIndexSeen = opIndex;
                }
                */

                // Flag reachedEndOfHistory as true if operation index is equal to or greater than the highest op index retrieved earlier
                if (searchType === "full" && !reachedEndOfHistory && opIndex >= senderHighestOpIndex) {
                    reachedEndOfHistory = true;
                }

                // Skip operation if its index is equal to or lower than the highest operation index seen
                if (searchType === "full" && opIndex <= highestOpIndexSeen) {
                    console.warn(`Skipping already processed message (by operation index) from sender ${senderName} at operation index ${opIndex}. Transaction ID: ${op.trx_id}`);
                    continue;
                }

                // Update highest operation index seen
                if (searchType === "full" && opIndex > highestOpIndexSeen) {
                    highestOpIndexSeen = opIndex;
                }

                if (op.op[0] === "custom_json") {
                    const customJson = op.op[1];

                    // Check whether the ID is "ჰ0"
                    if (customJson.id === "ჰ0") {

                        let jsonContent = null;
                        try {
                            jsonContent = JSON.parse(customJson.json);
                        } catch (err) {
                            console.warn(`Skipping malformed JSON from sender ${senderName} at operation index ${opIndex}. Error: ${err.message}`);
                            continue;
                        }

                        // Check for the presence of the მ key
                        if (!Object.prototype.hasOwnProperty.call(jsonContent, "მ")) {
                            console.warn(`Skipping message from sender ${senderName} at operation index ${opIndex}: Missing მ key.`);
                            continue;
                        }

                        /*
                        // Check whether the მ-content is a string
                        if (typeof jsonContent["მ"] !== "string") {
                            console.warn(`Skipping message from sender ${senderName} at operation index ${opIndex}: The მ-content is not a string.`);
                            continue;
                        }
                        */

                        // Check whether the მ-content is an empty string
                        if (typeof jsonContent["მ"] === "") {
                            console.warn(`Skipping message from sender ${senderName} at operation index ${opIndex}: The მ-content is an empty string.`);
                            continue;
                        }

                        // Debugging
                        // console.log("\"jsonContent[\"მ\"]\":", jsonContent["მ"]);

                        // Check whether the მ-content conforms with the expected character set
                        if (!(validateStringCharSet(jsonContent["მ"], customBase91CharSet))) {
                            console.warn(`Skipping message from sender ${senderName} at operation index ${opIndex}: The მ-content has invalid characters.`);
                            continue;
                        }

                        console.log(`Found matching "custom_json" from sender ${senderName} at operation index ${opIndex}.`);

                        // Perform decryption of message
                        const decrypted = await performMessageDecryption(
                            recipientName,
                            recipientPrivMemoKeys, // array of strings
                            recipientPrivPQkeys, // array of strings
                            senderName,
                            opIndex, // integer
                            jsonContent["მ"], // string
                        );

                        // Skip saving message if any required info is missing
                        if (
                            !decrypted
                            || typeof decrypted !== "string"
                            || decrypted.trim() === ""
                        ) {

                            /*
                            // Debugging
                            console.warn(`Failed to save message from sender ${senderName} at operation index ${opIndex}: "decrypted" returned as null.`);
                            */

                            continue;
                        }

                        // Store required info about successfully decrypted message
                        acquiredMessages.unshift({
                            block: op.block,
                            timestamp: op.timestamp,
                            tx_id: op.trx_id,
                            sender: senderName,
                            op_index: opIndex,
                            addressee: recipientName,
                            message: decrypted,
                            flags: {},
                        });
                    }
                }
            }

            // Exit the do/while loop if searchType is "light", or if reachedEndOfHistory is true
            if (searchType === "light" || reachedEndOfHistory) break;

            // If searchType is "full", apply a 1000 increment to start, so that more operations can be fetched
            if (searchType === "full") {
                start += limit;
            }

        } while (true);

        console.log(`
    Successfully acquired ${acquiredMessages.length} messages from ${senderName}.${searchType === "full" ? ` Updated highest operation index seen: ${highestOpIndexSeen}.` : ""}
        `);

        return {
            acquiredMessages,
            updatedOpIndexSeen: highestOpIndexSeen,
        };

    } catch (err) {
        console.error(`Failed to process messages from account ${senderName}. Error: ${err.message}`);
        throw err;
    }
}


// Update (synchronise) save file with onchain messages
export async function synchroniseSaveFile(
    recipientName,
    saveFileContents, // object
    searchType, // "full" or "light"
) {

    try {

        if (
            !Array.isArray(saveFileContents.accounts[recipientName].mail.messages_saved)
        ) {
            console.error(`Invalid save file structure.`);
            throw new Error(`Invalid save file structure.`);
        }

        console.log(`Starting message retrieval process...`);

        // Validate sender accounts
        const validSenders = await validateExpectedSenders(
            Object.keys(saveFileContents.accounts[recipientName].mail.contacts), // flat array of strings
            saveFileContents.nodes.filter(([_, value]) => value === 1).map(([str]) => str), // flat array of strings
        );

        if (validSenders.length === 0) {
            console.error(`No valid senders found.`);
            throw new Error(`No valid senders found.`);
        }

        // Create a set of existing transaction IDs from "messages saved"
        const savedTxIds = new Set(saveFileContents.accounts[recipientName].mail.messages_saved.map(msg => msg.tx_id));

        /*
        // Debugging
        console.log("\"savedTxIds\" contents:", savedTxIds);
        */

        // Create an empty array where all new found messages will be saved
        const allNewMessages = [];

        for (const sender of validSenders) {

            const {
                acquiredMessages,
                updatedOpIndexSeen,
            } = await fetchMessagesForAccount(
                saveFileContents.nodes.filter(([_, value]) => value === 1).map(([str]) => str), // flat array of strings
                recipientName,
                saveFileContents.accounts[recipientName].mail.memo_keys.filter(([_, value]) => value === 1).map(([str]) => "5" + str), // flat array of strings
                saveFileContents.accounts[recipientName].mail.pq_keys.filter(([_, value]) => value === 1).map(([str]) => str), // flat array of strings
                sender,
                saveFileContents.accounts[recipientName].mail.contacts[sender].op_index_seen, // integer
                searchType,
            );

            // Skip to next sender if the acquiredMessages array is somehow missing
            if (!acquiredMessages || !Array.isArray(acquiredMessages)) {
                continue;
            }

            // If updatedOpIndexSeen was received, update op_index_seen for this sender
            if (updatedOpIndexSeen) {
               saveFileContents.accounts[recipientName].mail.contacts[sender].op_index_seen = updatedOpIndexSeen;
            }

            // Filter new messages based on transaction ID (add only if message is actually new)
            for (const msg of acquiredMessages) {
                if (msg.tx_id && !savedTxIds.has(msg.tx_id)) {
                    allNewMessages.unshift(msg);
                    savedTxIds.add(msg.tx_id);
                }
            }
        }

        // Merge and sort all messages in reverse chronological order
        saveFileContents.accounts[recipientName].mail.messages_saved = saveFileContents.accounts[recipientName].mail.messages_saved
            .concat(allNewMessages)
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        return saveFileContents;

    } catch (err) {
        console.error(`Save file synchronisation failed. Error: ${err.message}`);
        throw err;
    }
}








