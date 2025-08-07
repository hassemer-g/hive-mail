import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

import {
    Client,
    PrivateKey,
} from "@hiveio/dhive";
import {
    utf8ToBytes,
    bytesToUtf8,
} from "@noble/hashes/utils";

import { testRPCs } from "./test_rpcs.js";
import {
    validateAccountNameStructure,
    validateHivePrivKey,
} from "./sync_aux_fxs.js";
import {
    fetchLatestOpIndex,
    fetchCurrentPubKeys,
    testHiveKeys,
    testOpIndexSeen,
} from "./async_aux_fxs.js";
import { derivForSaveFile } from "./deriv_for_save.js";
import { synchroniseSaveFile } from "./read_pq.js";
import { broadcastEncryptedMessage } from "./send_pq.js";

import {
    validatePrivPQkey,
    validatePubPQkey,
    derivePQkeyPair,
    extractKyberPublicKey,
} from "../[LIB]/pq.js";
import {
    customBase91CharSet,
} from "../[LIB]/charsets.js";
import {
    bytesToBase91,
    bytesFromBase91,
} from "../[LIB]/custom_base91.js";
import { shuffleArray } from "../[LIB]/shuffle_array.js";
import { generateRandomString } from "../[LIB]/generate_random_string.js";
import {
    encryptXChaCha20Poly1305,
    decryptXChaCha20Poly1305,
} from "../[LIB]/xchacha20_poly1305.js";
import { promptUserInputReadline } from "../[LIB]/synchronous_prompt.js";


// Convert import.meta.url to a file path
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


// ==================================================================== //


/*
 *
 *
 * PQ-KEYS RELATED
 *
 *
 */

// Broadcast operation to update the public PQ key
async function updatePQkey(
    accountName,
    userPrivPostingKey, // string
    postingMetadata, // object
    RPCs, // flat array of strings
) {

    try {

        if (
            !postingMetadata
            || typeof postingMetadata !== "object"
            || Array.isArray(postingMetadata)
            || !postingMetadata?.["ჰ0"]
            || typeof postingMetadata?.["ჰ0"] !== "object"
            || Array.isArray(postingMetadata?.["ჰ0"])
            || !validatePubPQkey(postingMetadata?.["ჰ0"]?.["ქ"])
        ) {
            throw new Error(`Invalid Public Post-Quantum Key received!`);
        }

        const op = [
            "account_update2", {
                account: accountName,
                extensions: [],
                json_metadata: "",
                posting_json_metadata: JSON.stringify(postingMetadata, null, 0),
            }
        ];

        console.log(`Prepared "account_update2" operation: ${JSON.stringify(op, null, 2)}`);

        // Sign and broadcast
        const key = PrivateKey.fromString(userPrivPostingKey);

        console.log(`Broadcasting transaction...`);

        const result = await new Client(shuffleArray(RPCs)).broadcast.sendOperations([op], key);

        console.log(`Transaction successfully broadcast. Transaction ID: ${result.id}`);

    } catch (err) {
        console.error(`Failed to broadcast your updated Public Post-Quantum Key. Error: ${err.message}`);
        throw err;
    }
}


// Check the status of the currently registered public PQ key, and update it if needed
async function checkPubliclyRegisteredKeys(
    accountName, // string
    userPrivPostingKey, // string
    userPubPQkey, // string, Base91
    RPCs, // flat array of strings
) {

    try {

        const [accountData] = await new Client(shuffleArray(RPCs)).database.getAccounts([accountName]);

        if (!accountData) {
            throw new Error(`Account "${accountName}" not found.`);
        }

        let postingMetadata = {};
        let invalidPostingMetadata = false;

        if (!accountData.posting_json_metadata) {

            postingMetadata["ჰ0"] = {};
            postingMetadata["ჰ0"]["ქ"] = "";
            invalidPostingMetadata = true;
        }

        if (!invalidPostingMetadata) {
            try {
                postingMetadata = JSON.parse(accountData.posting_json_metadata);

            } catch (err) {
                // Invalid JSON, reset it
                postingMetadata = {};
                postingMetadata["ჰ0"] = {};
                postingMetadata["ჰ0"]["ქ"] = "";
                invalidPostingMetadata = true;
            }
        }

        if (
            !invalidPostingMetadata &&
            (!postingMetadata || typeof postingMetadata !== "object" || Array.isArray(postingMetadata))
        ) {

            postingMetadata = {};
            postingMetadata["ჰ0"] = {};
            postingMetadata["ჰ0"]["ქ"] = "";
            invalidPostingMetadata = true;
        }

        if (
            !invalidPostingMetadata &&
            (!postingMetadata["ჰ0"] || typeof postingMetadata["ჰ0"] !== "object" || Array.isArray(postingMetadata["ჰ0"]))
        ) {

            postingMetadata["ჰ0"] = {};
            postingMetadata["ჰ0"]["ქ"] = "";
            invalidPostingMetadata = true;
        }

        if (
            !invalidPostingMetadata && typeof postingMetadata["ჰ0"]["ქ"] !== "string"
        ) {

            postingMetadata["ჰ0"]["ქ"] = "";
            invalidPostingMetadata = true;
        }

        if (!invalidPostingMetadata) {
            console.log(`
    Current registered Public Post-Quantum Key for ${accountName}:
    ${postingMetadata["ჰ0"]["ქ"]}
            `);
        }

        // If existing metadata key is different than the updated metadata key, update it
        let updateNeeded = false;

        if (postingMetadata["ჰ0"]["ქ"] !== userPubPQkey) {
            postingMetadata["ჰ0"]["ქ"] = userPubPQkey;
            updateNeeded = true;
        }

        /*
        // Debugging
        console.log("\"postingMetadata[\"ჰ0\"][\"ქ\"]\":", postingMetadata["ჰ0"]["ქ"]);
        // console.log(bytesFromBase91(postingMetadata["ჰ0"]["ქ"]).byteLength);
        console.log(`
    Comparing previous and updated posting metadata for ${accountName}:

    Previous:
    ${accountData.posting_json_metadata}

    Updated:
    ${JSON.stringify(postingMetadata, null, 0)}
        `);
        */

        if (updateNeeded) {
            // Broadcast account_update2 operation to update posting metadata
            await updatePQkey(
                accountName,
                userPrivPostingKey,
                postingMetadata,
                RPCs,
            );

        } else {
            console.log(`No updates needed for your metadata public keys.`);
        }

    } catch (err) {
        console.error(`Failed to retrieve or update the metadata public keys for account ${accountName}. Error: ${err.message}`);
        throw err;
    }
}


/*
 *
 *
 * DISPLAY MESSAGES
 *
 *
 */

function displaySavedMessages(
    savedMessages, // array
    userName,
) {

    if (!Array.isArray(savedMessages) || savedMessages.length === 0) {
        console.log(`No saved messages found.`);
        return;
    }

    // Group messages by sender
    const groupedBySender = {};
    for (const msg of savedMessages) {
        const sender = msg.sender || "Unknown Sender";
        if (!groupedBySender[sender]) {
            groupedBySender[sender] = [];
        }
        groupedBySender[sender].push(msg);
    }

    // Sort senders alphabetically, keeping the user account in the first position
    const senders = Object.keys(groupedBySender)
        .sort()
        .sort((a, b) => (a === userName ? -1 : b === userName ? 1 : 0));

    console.log(`\n=== Saved Messages ===\n`);

    for (const sender of senders) {
        const messages = groupedBySender[sender];

        // Sort messages by reverse timestamp
        messages.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

        console.log(`\nFrom: ${sender}${sender === userName ? " (YOURSELF)" : ""}`);
        console.log("-".repeat(50));

        for (const msg of messages) {
            console.log(`• [${msg.timestamp}]`);
            // console.log(`  Transaction ID  : ${msg.tx_id}\n`);
            console.log(`  Operation Index : ${msg.op_index}`);
            console.log(`  Message         : ${msg.message}${sender === userName ? "" : "\n"}`);
            if (sender === userName) console.log(`  Addressee       : ${msg.addressee}\n`);
        }
    }

    console.log("=== End of Saved Messages ===\n");
}


/*
 *
 *
 * READ AND PROCESS EXISTING SAVE FILE
 *
 *
 */

// Prompt the user on what to do
async function promptWhatToDo(
    userName, // string
    saveFilePassw, // string
    saveFilePIN, // string
    saveFileContents, // object
    saveDir,
    saveFilePath,
) {

    try {

        console.log(`
    Save file successfully loaded. What would you like to do now?
        `);

        // Prompt user on what to do
        let userActionChoice;
        do {
            userActionChoice = promptUserInputReadline(`
    Enter "1" to read your saved messages (in reverse chronological order);
    Enter "2" to broadcast an encrypted message;
    Enter "3" to synchronise your save file with newly-received messages;
    Enter "4" to alter your save file (change password, keys, add contacts, etc.) and save it;
    Enter "5" to export your saved messages to an unencrypted JSON file;
    Enter "6" to reset saved info on already seen transactions;
    Enter "7" to disable all Memo Keys and Post-Quantum Keys, except the most recent of each (this makes decryption of onchain data much quicker);
    Enter "8" to enable all Memo Keys and Post-Quantum Keys (this makes decryption of onchain data take longer, but allows decryption of data encrypted before your latest change of keys);
    Enter "9" to change your Post-Quantum Key;
    Enter "10" to export your Post-Quantum Keys to an unencrypted JSON file;
    Enter "11" to add a Hive RPC to the RPC list;
    Enter "12" to test the saved RPCs and disable those unresponsive;
    Or enter "0" to quit without saving, or "00" to save and exit.

    Your choice: `,
            () => true, // Accept any input
            );

            if (userActionChoice === "0") { // exit without saving
                console.log(`Exiting...`);
                break;

            } else if (userActionChoice === "00") { // save then exit

                // Save file
                await doSaveFile(saveFilePassw, saveFilePIN, saveFileContents, saveDir, saveFilePath);

                console.log(`Successfully saved. Now exiting...`);
                break;

            } else if (userActionChoice === "1") { // read your saved messages (in reverse chronological order)

                displaySavedMessages(
                    saveFileContents.accounts[userName].mail.messages_saved,
                    userName,
                );

            } else if (userActionChoice === "2") { // broadcast an encrypted message

                try {

                    // Prompt for the recipient account name
                    const excludeAccounts = [
                        userName,
                    ];

                    const recipient = promptUserInputReadline(
                        `Enter the recipient account name: `,
                        validateAccountNameStructure,
                        false,
                        null,
                        0,
                        excludeAccounts,
                    );

                    // Check whether chosen recipient is already included in contacts
                    if (
                        recipient
                        && !saveFileContents.accounts[userName].mail.contacts.hasOwnProperty(recipient)
                    ) {
                        console.warn(`The chosen recipient ${recipient} is not yet included in your contacts. Add it to your contacts first, then try again.`);
                        continue;
                    }

                    // Check whether user has the required keys
                    if (
                        !(saveFileContents.accounts[userName].mail.pq_keys.flat().some(str => typeof str === "string" && str.length > 0))
                    ) {
                        console.warn(`You must have a Post-Quantum Key in order to send encrypted messages using Hive Mail.`);
                        continue;
                    }

                    // Check whether recipient has the required keys
                    const {
                        pubMemoKey: recipientPubMemoKey,
                        pubPQkey: recipientPubPQkey,
                    } = await fetchCurrentPubKeys(
                        recipient,
                        saveFileContents.nodes.filter(([_, value]) => value === 1).map(([str]) => str), // flat array of strings
                    );

                    if (
                        !recipientPubMemoKey
                        || !recipientPubPQkey
                    ) {
                        console.warn(`Recipient does not have the required public keys registered!`);
                        continue;
                    }

                    const messageInputFile = "message_to_broadcast.txt";
                    const messageInputFilePath = path.join(saveDir, messageInputFile);

                    console.log(`
    To input the plaintext (i.e., the unencrypted message) to be broadcast, you can provide it in a file named ${messageInputFile}, which must be in the same directory as this script file, or alternatively you can type or paste the text in this terminal.
                    `);

                    let unencryptedMessageToSend = null;

                    // Take message from message file if it exists
                    if (fs.existsSync(messageInputFilePath)) {

                        unencryptedMessageToSend = fs.readFileSync(messageInputFilePath, "utf8").trim();
                    }

                    if (typeof unencryptedMessageToSend !== "string" || unencryptedMessageToSend.trim() === "") {

                        // Prompt for message to send
                        unencryptedMessageToSend = promptUserInputReadline(`
    Enter (recommended: paste) below your unencrypted message, to be encrypted and broadcast:

`,
                            (input) => input.trim() !== "",
                        );
                    } else {
                        console.log(`The unencrypted message to encrypt and broadcast will be taken from the file ${messageInputFile}`);
                    }

                    const broadcastMessage = await broadcastEncryptedMessage(
                        userName,
                        "5" + saveFileContents.accounts[userName].posting_key, // string
                        recipient,
                        recipientPubMemoKey, // string
                        recipientPubPQkey, // string
                        saveFileContents.nodes.filter(([_, value]) => value === 1).map(([str]) => str), // flat array of strings
                        unencryptedMessageToSend,
                    );

                    if (broadcastMessage) {
                        // Add message object in the first position
                        saveFileContents.accounts[userName].mail.messages_saved.unshift(broadcastMessage);

                        // Save file
                        await doSaveFile(saveFilePassw, saveFilePIN, saveFileContents, saveDir, saveFilePath);

                    } else {
                        console.error(`Failed to broadcast encrypted message.`);
                    }
                } catch (err) {
                    console.error(`Failed to broadcast encrypted message. Error: ${err.message}`);
                    // continue;
                }

            } else if (userActionChoice === "3") { // synchronise your save file with newly-received messages

                try {

                    // Choose whether to perform a full check (starting from oldest operation) or a "light" check (fetch only the 1000 most recent operations per contact)
                    const searchTypeChoice = parseInt(promptUserInputReadline(`
    Choose search type:

    FULL SEARCH: Hive operations are processed from older to newer (chronological order). The highest operation index seen for each contact is saved. The search is conducted starting from the previous highest operation index seen for each contact. This search mode is slower but more reliable.
    Warning: The first FULL SEARCH can take a long time, especially for contacts with extensive account history.

    LIGHT SEARCH: Searches for messages only among the 1000 most recent operations for each contact. Operations are processed from newer to older (reverse chronological order). The highest operation index seen for each contact is NOT saved. This search mode is quicker, but might not fetch older messages sent to you.

    If this is your first search, I strongly recommend you choose FULL SEARCH.

    Your choice (1 = FULL SEARCH, 2 = LIGHT SEARCH, 0 = abort search): `,
                        (input) => ["0", "1", "2"].includes(input), // Ensures valid input
                    ));
                    if (!Number.isInteger(searchTypeChoice) || searchTypeChoice === 0) {
                        continue;
                    }
                    const searchType = searchTypeChoice === 2 ? "light" : "full";

                    // Call synchronisation function
                    const updatedSaveFileContents = await synchroniseSaveFile(
                        userName,
                        saveFileContents, // object
                        searchType,
                    );

                    if (
                        updatedSaveFileContents
                        && typeof updatedSaveFileContents === "object"
                        && !Array.isArray(updatedSaveFileContents)
                    ) {
                        saveFileContents = updatedSaveFileContents;

                        console.log(`Successfully synchronised your save file. Starting now the saving process...`);

                        // Save file
                        await doSaveFile(saveFilePassw, saveFilePIN, saveFileContents, saveDir, saveFilePath);

                        console.log(`Saved successfully.`);

                    } else {
                        console.error(`Failed to synchronise your save file.`);
                    }
                } catch (err) {
                    console.error(`Failed to synchronise your save file. Error: ${err.message}`);
                    // continue;
                }

            } else if (userActionChoice === "4") { // alter your save file (change password, keys, add contacts, etc.), then save changes

                try {

                    // Ask for password and PIN before altering save file
                    console.log(`For the sake of security, before proceeding with the alteration of your save file, you must re-enter your save file password and PIN.`);

                    const inputSaveFilePassw = promptUserInputReadline(
                        `Re-enter the password to the save file: `,
                        validatePassw,
                        true,
                        "",
                    );

                    const inputSaveFilePIN = promptUserInputReadline(
                        `Re-enter the save file's PIN: `,
                        (input) => /^\d{4,16}$/.test(input), // Only digits, length 4–16
                        true,
                        "",
                    );

                    if (
                        inputSaveFilePassw !== saveFilePassw
                        || inputSaveFilePIN !== saveFilePIN
                    ) {
                        console.error(`Error: Incorrect credentials provided.`);
                        continue;
                    }

                    // Run the change save file function and get updated save file contents
                    const {
                        updatedSaveFilePassw,
                        updatedSaveFilePIN,
                        updatedSaveFileContents,
                    } = await alterSaveFile(
                        userName,
                        saveFilePassw,
                        saveFilePIN,
                        saveFileContents,
                    );

                    if (
                        typeof updatedSaveFilePassw === "string"
                        && typeof updatedSaveFilePIN === "string"
                        && typeof updatedSaveFileContents === "object"
                        && !Array.isArray(updatedSaveFileContents)
                        // && typeof updatedSaveFileContents.accounts[userName] === "object"
                    ) {

                        saveFilePassw = updatedSaveFilePassw;
                        saveFilePIN = updatedSaveFilePIN;
                        saveFileContents = updatedSaveFileContents;

                        console.log(`Finished altering your save file. Starting now the saving process...`);

                        // Save file
                        await doSaveFile(saveFilePassw, saveFilePIN, saveFileContents, saveDir, saveFilePath);

                        console.log(`Successfully altered your save file and saved it.`);

                    } else {
                        console.error(`Failed to alter your save file.`);
                    }
                } catch (err) {
                    console.error(`Failed to alter your save file. Error: ${err.message}`);
                }

            } else if (userActionChoice === "5") { // export your saved messages to an unencrypted JSON file

                try {

                    // Ask for password and PIN before saving unencrypted data
                    console.log(`For the sake of security, before proceeding with the export of data to an unencrypted file, you must re-enter your save file password and PIN.`);

                    const inputSaveFilePassw = promptUserInputReadline(
                        `Re-enter the password to the save file: `,
                        validatePassw,
                        true,
                        "",
                    );

                    const inputSaveFilePIN = promptUserInputReadline(
                        `Re-enter the save file's PIN: `,
                        (input) => /^\d{4,16}$/.test(input), // Only digits, length 4–16
                        true,
                        "",
                    );

                    if (
                        inputSaveFilePassw !== saveFilePassw
                        || inputSaveFilePIN !== saveFilePIN
                    ) {
                        console.error(`Error: Incorrect credentials provided.`);
                        continue;
                    }

                    const exportedMessagesFile = "exported_messages.json";
                    const exportedMessagesFilePath = path.join(saveDir, exportedMessagesFile);

                    // Save unencrypted messages array
                    fs.writeFileSync(exportedMessagesFilePath, JSON.stringify({ messages_saved: saveFileContents.accounts[userName].mail.messages_saved }, null, 2), "utf8");

                    console.log(`
    Saved messages successfully exported to an unencrypted JSON file named ${exportedMessagesFile}.
                    `);

                } catch (err) {
                    console.error(`Failed to export your saved messages. Error: ${err.message}`);
                }

            } else if (userActionChoice === "6") { // reset saved info on already seen transactions and operation indices

                try {

                    // Ask for an explicit confirmation before wiping data on already seen ops
                    const explicitConfirm = promptUserInputReadline(
                        `
    Enter "9" to confirm you want to wipe all saved data on already seen operations, or enter any other input to cancel: `,
                        () => true, // Accept any input
                    );

                    if (explicitConfirm !== "9") {
                        continue;
                    }

                    // Reset to 0 the op_index_seen for every contact
                    for (const contact of Object.values(saveFileContents.accounts[userName].mail.contacts)) {
                        contact.op_index_seen = 0;
                    }

                    // Save file
                    // await doSaveFile(saveFilePassw, saveFilePIN, saveFileContents, saveDir, saveFilePath);

                    console.log(`
    Saved information on already seen operations successfully erased. Changes have not been saved yet!
    Attention: The next synchronisation might take much longer to complete.
                    `);

                } catch (err) {
                    console.error(`Failed to reset saved info on already seen transactions. Error: ${err.message}`);
                }

            } else if (userActionChoice === "7") { // disable all memo keys and post-quantum keys, except the most recent of each

                try {

                    for (let i = 1; i < saveFileContents.accounts[userName].mail.memo_keys.length; i++) {
                        saveFileContents.accounts[userName].mail.memo_keys[i][1] = 0;
                    }

                    for (let i = 1; i < saveFileContents.accounts[userName].mail.pq_keys.length; i++) {
                        saveFileContents.accounts[userName].mail.pq_keys[i][1] = 0;
                    }

                    // Save file
                    // await doSaveFile(saveFilePassw, saveFilePIN, saveFileContents, saveDir, saveFilePath);

                    console.log(`
    All your Memo Keys and Post-Quantum Keys, except the most recent of each, successfully disabled.
                    `);

                } catch (err) {
                    console.error(`Failed to disable older Memo Keys and Post-Quantum Keys. Error: ${err.message}`);
                }

            } else if (userActionChoice === "8") { // enable all memo keys and PQ keys

                try {

                    for (let i = 0; i < saveFileContents.accounts[userName].mail.memo_keys.length; i++) {
                        saveFileContents.accounts[userName].mail.memo_keys[i][1] = 1;
                    }

                    for (let i = 0; i < saveFileContents.accounts[userName].mail.pq_keys.length; i++) {
                        saveFileContents.accounts[userName].mail.pq_keys[i][1] = 1;
                    }

                    // Save file
                    // await doSaveFile(saveFilePassw, saveFilePIN, saveFileContents, saveDir, saveFilePath);

                    console.log(`
    All your Memo Keys and Post-Quantum Keys successfully enabled.
                    `);

                } catch (err) {
                    console.error(`Failed to enable older Memo Keys and Post-Quantum Keys. Error: ${err.message}`);
                }

            } else if (userActionChoice === "9") { // change your Post-Quantum Key

                try {

                    // Ask for an explicit confirmation before proceeding
                    const explicitConfirm = promptUserInputReadline(
                        `
    Enter "9" to confirm you want to change your Post-Quantum Key, or enter any other input to cancel: `,
                        () => true, // Accept any input
                    );

                    if (explicitConfirm !== "9") {
                        continue;
                    }

                    // Derive a new PQ keypair
                    const { privKey, pubKey } = await derivePQkeyPair(); // both Uint8Array
                    const updatedPrivPQkey = bytesToBase91(privKey);
                    const updatedPubPQkey = bytesToBase91(pubKey);

                    // Register onchain the new public Post-Quantum key
                    await checkPubliclyRegisteredKeys(
                        userName,
                        "5" + saveFileContents.accounts[userName].posting_key, // string
                        updatedPubPQkey, // string, Base91
                        saveFileContents.nodes.filter(([_, value]) => value === 1).map(([str]) => str), // flat array of strings
                    );

                    // Add the new PQ key to the PQ keys array, in the first position, filtering out repeated keys
                    let existingPQkeys = saveFileContents.accounts[userName].mail.pq_keys.map(([str]) => str);
                    existingPQkeys = [updatedPrivPQkey, ...existingPQkeys];

                    // Remove duplicates, keeping the first occurrence
                    const seenPQkeys = new Set();
                    const uniquePQkeys = [];
                    for (const key of existingPQkeys) {
                        if (key && !seenPQkeys.has(key)) {

                            seenPQkeys.add(key);

                            uniquePQkeys.push([ key, 1 ]);
                        }
                    }

                    saveFileContents.accounts[userName].mail.pq_keys = uniquePQkeys;

                    // Save file
                    await doSaveFile(saveFilePassw, saveFilePIN, saveFileContents, saveDir, saveFilePath);

                    console.log(`
    Post-Quantum Key successfully altered, and changes saved. Attention: all your Post-Quantum Keys have been enabled.
                    `);

                } catch (err) {
                    console.error(`Failed to change your Post-Quantum Key. Error: ${err.message}`);
                    throw err;
                }

            } else if (userActionChoice === "10") { // export your Post-Quantum Keys to an unencrypted JSON file

                try {

                    // Ask for password and PIN before saving unencrypted data
                    console.log(`For the sake of security, before proceeding with the export of data to an unencrypted file, you must re-enter your save file password and PIN.`);

                    const inputSaveFilePassw = promptUserInputReadline(
                        `Re-enter the password to the save file: `,
                        validatePassw,
                        true,
                        "",
                    );

                    const inputSaveFilePIN = promptUserInputReadline(
                        `Re-enter the save file's PIN: `,
                        (input) => /^\d{4,16}$/.test(input), // Only digits, length 4–16
                        true,
                        "",
                    );

                    if (
                        inputSaveFilePassw !== saveFilePassw
                        || inputSaveFilePIN !== saveFilePIN
                    ) {
                        console.error(`Error: Incorrect credentials provided.`);
                        continue;
                    }

                    const exportedPQkeysFile = "pq_keys.json";
                    const exportedPQkeysFilePath = path.join(saveDir, exportedPQkeysFile);

                    // Write unencrypted JSON file
                    fs.writeFileSync(exportedPQkeysFilePath, JSON.stringify({ pq_keys: saveFileContents.accounts[userName].mail.pq_keys.map(([str]) => str) }, null, 2), "utf8");

                    console.log(`
    Post-Quantum Keys successfully exported to an unencrypted JSON file named ${exportedPQkeysFile}.
                    `);

                } catch (err) {
                    console.error(`Failed to export your Post-Quantum Keys. Error: ${err.message}`);
                }

            } else if (userActionChoice === "11") { // add a Hive RPC to the RPC list

                try {
                    const rpcToAdd = promptUserInputReadline(
                        `Enter the URL of the RPC to be added: `,
                        (input) => input.trim() !== "",
                        false,
                        null,
                        0,
                        saveFileContents.nodes.map(([str]) => str),
                    );

                    // Test the new RPC
                    const testedRPC = await testRPCs([ rpcToAdd ]); // returns an array

                    /*
                    // Debugging
                    console.log(testedRPC === [ rpcToAdd ]);
                    console.log("\"testedRPC\":", testedRPC);
                    console.log("\"testedRPC\" length:", testedRPC.length);
                    console.log(Array.isArray(testedRPC));
                    console.log(testedRPC.every(item => typeof item === "string"));
                    console.log("\"[ rpcToAdd ]\":", [ rpcToAdd ]);
                    console.log("\"[ rpcToAdd ]\" length:", [ rpcToAdd ].length);
                    console.log(Array.isArray([ rpcToAdd ]));
                    console.log([ rpcToAdd ].every(item => typeof item === "string"));
                    */

                    if (testedRPC.length === 1 && testedRPC[0] === rpcToAdd) {

                        // Add the new RPC to the RPCs array, in the first position, filtering out repeated RPCs
                        let existingRPCs = saveFileContents.nodes.map(([str]) => str);
                        existingRPCs = [rpcToAdd, ...existingRPCs];

                        // Remove duplicates, keeping the first occurrence
                        const seenRPCs = new Set();
                        const uniqueRPCs = [];
                        for (const RPC of existingRPCs) {
                            if (RPC && !seenRPCs.has(RPC)) {

                                seenRPCs.add(RPC);

                                uniqueRPCs.push([ RPC, 1 ]);
                            }
                        }

                        saveFileContents.nodes = uniqueRPCs;

                        // Test all saved RPCs including the new one
                        const responsiveRPCs = await testRPCs(saveFileContents.nodes.map(([str]) => str)); // returns an array of strings

                        if (responsiveRPCs.length > 0) {

                            const responsiveRPCsSet = new Set(responsiveRPCs);
                            saveFileContents.nodes = saveFileContents.nodes.map(([str, _]) => [str, responsiveRPCsSet.has(str) ? 1 : 0]);

                            // Save file
                            await doSaveFile(saveFilePassw, saveFilePIN, saveFileContents, saveDir, saveFilePath);

                            console.log(`
    New RPC added successfully. All saved RPCs including the new one tested successfully, only the responsive ones are active now. Changes successfully saved.
                            `);

                        } else {
                            console.error(`
    All saved RPCs including the new one failed the test. Try again later.
                            `);
                        }

                    } else {
                        console.error(`
    Failed to add new RPC.
                        `);
                    }
                } catch (err) {
                    console.error(`
    Failed to add new RPC. Error: ${err.message}
                    `);
                }

            } else if (userActionChoice === "12") { // test saved RPCs and disable those unresponsive

                try {
                    // Test saved RPCs
                    const responsiveRPCs = await testRPCs(saveFileContents.nodes.map(([str]) => str)); // returns an array of strings

                    if (responsiveRPCs.length > 0) {

                        const responsiveRPCsSet = new Set(responsiveRPCs);
                        saveFileContents.nodes = saveFileContents.nodes.map(([str, _]) => [str, responsiveRPCsSet.has(str) ? 1 : 0]);

                        // Save file
                        // await doSaveFile(saveFilePassw, saveFilePIN, saveFileContents, saveDir, saveFilePath);

                        console.log(`
    All saved RPCs were tested; only the responsive ones are now enabled.
                        `);

                    } else {
                        console.error(`All saved RPCs failed the test. No changes were applied; try again later.`);
                    }
                } catch (err) {
                    console.error(`Failed to test the saved RPCs. Error: ${err.message}`);
                }

            } else {
                console.error(`Invalid input. Try again.`);
            }

        } while (true);

        return;

    } catch (err) {
        console.error(`Failure! Error: ${err.message}`);
        throw err;
    }
}


// Load, read and decrypt save file
export async function loadSaveFile(
    userName,
    saveDir,
    saveFilePath,
) {

    try {

        // Abort if username is missing
        if (!userName) {
            console.error(`Error: Hive account name missing.`);
            return;
        }

        // Abort if save file is missing
        if (!fs.existsSync(saveFilePath)) {
            console.error(`Error: Save file not found.`);
            return;
        }

        const fileData = fs.readFileSync(saveFilePath, "utf8").trim();
        const parsedFile = JSON.parse(fileData);

        // Abort if salt or data are missing or empty
        if (
            !parsedFile.salt
            || parsedFile.salt.trim() === ""
            || !parsedFile.data
            || parsedFile.data.trim() === ""
        ) {
            console.error(`Invalid file format: Missing or empty required fields (salt or data).`);
            return;
        }

        // Prompt for the save file password
        let saveFilePassw = promptUserInputReadline(
            `Enter the password to the save file: `,
            validatePassw,
            true,  // Hide input (password style)
            "",    // No masking character (completely hidden input)
        );

        // Prompt for the save file PIN
        let saveFilePIN = promptUserInputReadline(
            `Enter the save file's PIN: `,
            (input) => /^\d{4,16}$/.test(input), // Only digits, length 4–16
            true,
            "",
        );

        // Read, decrypt and load save file
        let saveFileContents = {};

        console.log(`Attempting to decrypt save file...`);

        // Derive key and passwords (outputs in Uint8Array)
        const { keyForEncrypt, nonceForEncrypt } = await derivForSaveFile(
            saveFilePassw,
            saveFilePIN,
            parsedFile.salt,
        );

        // Decrypt XChaCha20-Poly1305 (input in Base91, converted to Uint8Array before decryption; output in UTF-8)
        const decrypted = bytesToUtf8(decryptXChaCha20Poly1305(
            bytesFromBase91(parsedFile.data), // Uint8Array
            keyForEncrypt, // Uint8Array
            nonceForEncrypt, // Uint8Array
        ));

        if (!decrypted) {
            throw new Error(`Decryption of save file failed. Possible incorrect password or PIN, or corrupted data.`);
        }

        const parsedData = JSON.parse(decrypted);

        if (
            !parsedData
            || typeof parsedData !== "object"
            || Array.isArray(parsedData)
        ) {
            throw new Error(`Invalid data in save file.`);
        }

        console.log(`Decryption of save file successful.`);

        // Load and validate "mode"
        if (parsedData.global_flags?.mode !== "ჰ0") {
            throw new Error(`Invalid or missing mode in save file.`);
        } else {
            saveFileContents.global_flags = parsedData.global_flags;
        }

        // Load and validate "nodes" array
        if (
            !Array.isArray(parsedData.nodes)
            || Object.keys(parsedData.nodes).length === 0
        ) {
            throw new Error(`Invalid or missing "nodes" array in save file.`);
        } else {
            saveFileContents.nodes = parsedData.nodes;
        }

        // Load and validate "accounts" object
        if (
            !parsedData.accounts
            || typeof parsedData.accounts !== "object"
            || Array.isArray(parsedData.accounts)
            || Object.keys(parsedData.accounts).length === 0
        ) {
            throw new Error(`Invalid or missing "accounts" object in save file.`);
        } else {
            saveFileContents.accounts = parsedData.accounts;
        }

        /*
        // Save the user's account name in a constant (needed to reach nested objects)
        const userName = Object.keys(saveFileContents.accounts)[0];

        if (!userName) {
            throw new Error(`Unable to retrieve the name of your Hive account.`);
        }
        */

        // Validate required info from the "accounts" object
        if (
            !saveFileContents.accounts[userName].user_flags
            || typeof saveFileContents.accounts[userName].user_flags !== "object"
            || Array.isArray(saveFileContents.accounts[userName].user_flags)
            || typeof saveFileContents.accounts[userName].posting_key !== "string"
            || !saveFileContents.accounts[userName].mail
            || typeof saveFileContents.accounts[userName].mail !== "object"
            || Array.isArray(saveFileContents.accounts[userName].mail)
            || !Array.isArray(saveFileContents.accounts[userName].mail?.memo_keys)
            || saveFileContents.accounts[userName].mail?.memo_keys.length === 0
            || !Array.isArray(saveFileContents.accounts[userName].mail?.pq_keys)
            || saveFileContents.accounts[userName].mail?.pq_keys.length === 0
            || !saveFileContents.accounts[userName].mail?.contacts
            || typeof saveFileContents.accounts[userName].mail?.contacts !== "object"
            || Array.isArray(saveFileContents.accounts[userName].mail?.contacts)
            || Object.keys(saveFileContents.accounts[userName].mail?.contacts).length === 0
            || !Array.isArray(saveFileContents.accounts[userName].mail?.messages_saved)
        ) {
            console.error(`Error: Missing or invalid required info in the "accounts" object in the save file.`);
            throw new Error(`Missing or invalid required info in the "accounts" object in the save file.`);
        }

        console.log(`Starting the testing of the saved RPCs...`);

        // Test saved RPCs
        const responsiveRPCs = await testRPCs(saveFileContents.nodes.map(([str]) => str)); // returns an array of strings

        if (responsiveRPCs.length > 0) {

            const responsiveRPCsSet = new Set(responsiveRPCs);
            saveFileContents.nodes = saveFileContents.nodes.map(([str, _]) => [str, responsiveRPCsSet.has(str) ? 1 : 0]);

            console.log(`
    All saved RPCs were tested; only the responsive ones are now enabled.
            `);

        } else {
            console.error(`All saved RPCs failed the test. Try again later.`);
            throw new Error(`All saved RPCs failed the test.`);
        }

        // Prompt user on what to do
        await promptWhatToDo(
            userName, // string
            saveFilePassw, // string
            saveFilePIN, // string
            saveFileContents, // object
            saveDir,
            saveFilePath,
        );

        return;

    } catch (err) {
        console.error(`Failed to read, decrypt or process save file. Error: ${err.message}`);
        return;
        // throw err;
    }
}


/*
 *
 *
 * SAVE FILE
 *
 *
 */

// Execute file saving process
async function doSaveFile(
    saveFilePassw, // string
    saveFilePIN, // string
    saveFileContents, // non-empty object
    saveDir,
    saveFilePath,
) {

    try {

        if (
            !saveFileContents
            || typeof saveFileContents !== "object"
            || Array.isArray(saveFileContents)
            || Object.keys(saveFileContents).length === 0
        ) {
            throw new Error(`Data to be saved should be a non-empty object!`);
        }

        // Ensure the save folder exists
        if (!fs.existsSync(saveDir)) {
            fs.mkdirSync(saveDir, { recursive: true });
        }

        console.log(`Starting the saving process...`);

        /*
        // Save unencrypted copy, for debugging
        const fullPathUnencrypted = path.join(saveDir, "unencrypted_save_file.json");
        fs.writeFileSync(fullPathUnencrypted, JSON.stringify(saveFileContents, null, 2), "utf8");
        */

        // Generate random salt
        const salt = generateRandomString(50, customBase91CharSet);
        console.log("Salt:", salt);

        // Derive key, nonce and passwords (outputs in Uint8Array)
        const { keyForEncrypt, nonceForEncrypt } = await derivForSaveFile(
            saveFilePassw,
            saveFilePIN,
            salt,
        );

        /*
        // Debugging
        console.log("\"keyForEncrypt\":", keyForEncrypt);
        console.log("\"nonceForEncrypt\":", nonceForEncrypt);
        */

        // Encrypt using XChaCha20-Poly1305 (output converted to Base91)
        const data = bytesToBase91(encryptXChaCha20Poly1305(
            utf8ToBytes(JSON.stringify(saveFileContents, null, 0)), // Uint8Array
            keyForEncrypt, // Uint8Array
            nonceForEncrypt, // Uint8Array
        ));

        // Build object to save
        const encryptedObjectToSave = {
            salt,
            data,
        };

        // Save
        fs.writeFileSync(saveFilePath, JSON.stringify(encryptedObjectToSave, null, 2), "utf8"); // Write the structured JSON to the file

        console.log(`Saving process completed successfully.`);

    } catch (err) {
        console.error(`Error during saving process: ${err.message}`);
        throw err;
    }
}


// Update (change) save file
async function alterSaveFile(
    userName,
    saveFilePassw,
    saveFilePIN,
    saveFileContents,
) {

    try {

        // Prompt for updated private POSTING key (must be a valid private key)
        const newPostingKey = promptUserInputReadline(
            `Enter your Hive account's new Private Posting Key (or leave blank to keep unaltered): `,
            (input) => input === "" || validateHivePrivKey(input),
            true,
            "·",
        );

        // Prompt for updated private MEMO key (must be a valid private key)
        const newMemoKey = promptUserInputReadline(
            `Enter your Hive account's new Private Memo Key (or leave blank to keep unaltered): `,
            (input) => input === "" || validateHivePrivKey(input),
            true,
            "·",
        );

        // Get public keys to be tested
        const postingKeyPub = PrivateKey.fromString(newPostingKey ? newPostingKey : "5" + saveFileContents.accounts[userName].posting_key).createPublic().toString();
        const memoKeyPub = PrivateKey.fromString(newMemoKey ? newMemoKey : "5" + saveFileContents.accounts[userName].mail.memo_keys[0][0]).createPublic().toString();

        // Check whether the keys are correct
        const areNewKeysCorrect = await testHiveKeys(
            userName,
            postingKeyPub, // Public Posting Key as a string
            memoKeyPub, // Public Memo Key as a string
            saveFileContents.nodes.filter(([_, value]) => value === 1).map(([str]) => str), // flat array of strings
        );

        if (!areNewKeysCorrect) {
            throw new Error(`Incorrect Private Posting Key or Private Memo Key provided!`);
        }

        // Prompt the user for a new save file password (with confirmation)
        const newSaveFilePassw = promptUserInputReadline(
            `Enter a new password to the save file (or leave blank to keep unaltered): `,
            (input) => input === "" || validatePassw(input), // Accept blank, else validate password
            true,
            "",
            1, // Confirmation only if input is not empty
        );

        // Prompt the user for a new PIN (with confirmation)
        const newSaveFilePIN = promptUserInputReadline(
            `Enter a new PIN for the save file (or leave blank to keep unaltered): `,
            (input) => input === "" || /^\d{4,16}$/.test(input), // Accept empty or 4–16 digits
            true,
            "",
            1, // Confirmation only if input is not empty
        );

        // Ensure the "contacts" object exists
        if (
            typeof saveFileContents.accounts[userName].mail.contacts !== "object"
            || Array.isArray(saveFileContents.accounts[userName].mail.contacts)
        ) {
            saveFileContents.accounts[userName].mail.contacts = {};
        }

        // Prompt for contacts to be added or altered
        console.log(`
    You can now enter contact accounts to add or alter (or leave blank to skip this step or finish).
        `);

        while (true) {
            const excludeAccounts = [
                userName,
                // ...Object.keys(saveFileContents.accounts[userName].mail.contacts),
            ];

            const contact = promptUserInputReadline(
                `Contact account to add or alter: `,
                (input) => input === "" || validateAccountNameStructure(input),
                false,
                null,
                0,
                excludeAccounts,
            );

            if (!contact) break;

            if (
                saveFileContents.accounts[userName].mail.contacts.hasOwnProperty(contact)
            ) {
                console.log(`
    Contact ${contact} is already included in your contact list. You now have the opportunity to change the "highest operation seen" for this contact.
                `);
            }

            // Prompt for op index seen for this contact
            const opIndexInput = promptUserInputReadline(
                `
    If you want, you can set an "operation index seen" number for this contact, so that only operations newer than that will be searched; this makes the first search for incoming messages much quicker, especially for contacts with extensive account history.

    Alternatively, you can choose to set this number as that of the oldest operation in a single "query batch" for this contact; this is likely the best option for most users.

    Enter the desired "operation index seen" number, or leave empty to get onchain the recommended number: `,
                (input) => input === "" || /^([1-9]\d*|0)$/.test(input), // Empty input, or non-negative integer (zero allowed), no leading zeroes allowed
            );

            const opIndexSeen = await testOpIndexSeen(
                contact,
                opIndexInput, // string, can be empty
                saveFileContents.nodes.filter(([_, value]) => value === 1).map(([str]) => str), // flat array of strings
            );

            // Update contacts
            saveFileContents.accounts[userName].mail.contacts[contact] = {
                op_index_seen: opIndexSeen,
            };
        }

        // APPLY THE CHANGES TO THE SAVE FILE OBJECT

        // Update password, if provided
        if (newSaveFilePassw && saveFilePassw !== newSaveFilePassw) {
            saveFilePassw = newSaveFilePassw;
        }

        // Update PIN, if provided
        if (newSaveFilePIN && saveFilePIN !== newSaveFilePIN) {
            saveFilePIN = newSaveFilePIN;
        }

        // Update private POSTING key, if provided
        if (newPostingKey && saveFileContents.accounts[userName].posting_key !== newPostingKey.slice(1)) {
            saveFileContents.accounts[userName].posting_key = newPostingKey.slice(1);
        }

        // Update private MEMO key, if provided
        if (newMemoKey && saveFileContents.accounts[userName].mail.memo_keys[0][0] !== newMemoKey.slice(1)) {

            // Add the new key to the keys array, in the first position, filtering out repeated keys
            let existingMemoKeys = saveFileContents.accounts[userName].mail.memo_keys.map(([str]) => str);

            existingMemoKeys = [newMemoKey.slice(1), ...existingMemoKeys];

            // Remove duplicates, keeping the first occurrence
            const seenMemoKeys = new Set();
            const uniqueMemoKeys = [];
            for (const key of existingMemoKeys) {
                if (key && !seenMemoKeys.has(key)) {

                    seenMemoKeys.add(key);

                    uniqueMemoKeys.push([ key, 1 ]);
                }
            }

            saveFileContents.accounts[userName].mail.memo_keys = uniqueMemoKeys;

            console.log(`
    The new Memo Key was successfully added, and set as current. Attention: all your Memo Keys have been enabled.
            `);
        }

        return {
            updatedSaveFilePassw: saveFilePassw,
            updatedSaveFilePIN: saveFilePIN,
            updatedSaveFileContents: saveFileContents,
        };

    } catch (err) {
        console.error(`An error occurred when altering your save file. Error: ${err.message}`);
        throw err;
    }
}


/*
 *
 *
 * BUILD NEW SAVE FILE
 *
 *
 */

// Validate password
function validatePassw(
    input, // string
) {

    if (input.length < 8) return false;

    // This regex matches any character that is NOT a digit or basic Latin letter (A-Z, a-z)
    // Unicode flag "u" ensures proper handling of modified letters like á, é, etc.
    const nonBasicLetterOrDigit = /[^0-9A-Za-z]/u;

    return nonBasicLetterOrDigit.test(input);
}


// Function to build a new save file
export async function buildNewSaveFile(
    userName,
    saveDir,
    saveFilePath,
) {

    try {

        // Abort if username is missing
        if (!userName) {
            console.error(`Error: Hive account name missing.`);
            return;
        }

        // Abort if save file is somehow NOT missing
        if (fs.existsSync(saveFilePath)) {
            console.error(`Error: Save file already exists.`);
            return;
        }

        console.log(`
    Starting the building of a new save file...
        `);

        // Hive RPCs
        const RPCs = shuffleArray([
            "https://api.hive.blog",
            // "https://api.openhive.network", // corrupts Base91 payloads, especially parts within < >
            "https://hive-api.arcange.eu",
            "https://rpc.mahdiyari.info",
            "https://hive-api.3speak.tv",
            "https://techcoderx.com",
            "https://api.deathwing.me",
            "https://anyx.io",
        ]).map(str => [str, 1]);

        // Prompt for current private posting key (must be a valid private key)
        const privPostingKey = promptUserInputReadline(
            `Enter your Hive account's current Private Posting Key: `,
            validateHivePrivKey,
            true,
            "·",
        );

        // Prompt for current private memo key (must be a valid private key)
        const privMemoKey = promptUserInputReadline(
            `Enter your Hive account's current Private Memo Key: `,
            validateHivePrivKey,
            true,
            "·",
        );

        // Check whether the provided Hive keys are correct
        const areKeysCorrect = await testHiveKeys(
            userName,
            PrivateKey.fromString(privPostingKey).createPublic().toString(), // Public Posting Key as a string
            PrivateKey.fromString(privMemoKey).createPublic().toString(), // Public Memo Key as a string
            RPCs.map(([str]) => str), // flat array of strings
        );

        if (!areKeysCorrect) {
            console.error(`Incorrect account name, Private Posting Key or Private Memo Key provided!`);
            return;
        }

        const privMemoKeys = [ [ privMemoKey.slice(1), 1 ] ];

        console.log(`
    The next step is choosing a strong password and a PIN to protect your save file. The password must contain at least 8 characters, and must contain at least one non-digit (0–9), non-letter (A–Z, a–z) character. As for the PIN, it must consist of 4 to 16 digits.
        `);

        // Prompt the user for the save file password (with confirmation)
        const saveFilePassw = promptUserInputReadline(
            `Enter and confirm a password to the save file (minimum 8 characters): `,
            validatePassw, // Ensure password has at least 8 character, and at least one non-digit, non-letter character
            true,
            "",
            2, // Requires input confirmation
        );

        // Prompt the user for a PIN (with confirmation)
        const saveFilePIN = promptUserInputReadline(
            `Enter and confirm a PIN for the save file (4 to 16 digits): `,
            (input) => /^\d{4,16}$/.test(input), // Only digits, length 4–16
            true,
            "",
            2, // Requires input confirmation
        );

        // Prompt for an existing private PQ key
        const existingPrivPQkey = promptUserInputReadline(
            `
    If you already have a Private Post-Quantum Key and would like to use it, enter it now, or leave empty to generate a new Post-Quantum Key Pair:

`,
            (input) => input === "" || validatePrivPQkey(input),
            true,
            "·",
        );

        let privPQkey = null;
        let pubPQkey = null;

        if (existingPrivPQkey) {

            privPQkey = existingPrivPQkey; // string, Base91
            pubPQkey = bytesToBase91(extractKyberPublicKey(bytesFromBase91(privPQkey))); // output a string, Base91

            /*
            // Debugging
            console.log("existing \"privPQkey\":", privPQkey);
            console.log("existing \"pubPQkey\":", pubPQkey);
            */

        } else {

            console.log("Generating now a new Post-Quantum Keypair...");
            // Derive a new Post-Quantum key pair
            const { privKey, pubKey } = await derivePQkeyPair(); // both Uint8Array
            privPQkey = bytesToBase91(privKey);
            pubPQkey = bytesToBase91(pubKey);

            /*
            // Debugging
            console.log("new \"privPQkey\":", privPQkey);
            console.log("new \"pubPQkey\":", pubPQkey);
            */

        }

        try {
            // Register onchain the public version of the special keys
            await checkPubliclyRegisteredKeys(
                userName,
                privPostingKey, // string
                pubPQkey, // string, Base91
                RPCs.map(([str]) => str), // flat array of strings
            );

        } catch (err) {
            console.error(`Failed to register onchain your special keys! Error: ${err.message}`);
            throw err;
        }

        // Build the PQ keys array
        const privPQkeys = [ [ privPQkey, 1 ] ];

        console.log(`
    Hive account successfully imported. Now let's add contacts to your save file. Contact accounts will be listened for encrypted messages directed to you onchain. Furthermore, you will be able to send encrypted messages to them.

    You must enter at least one contact now; you will be able to add more contacts later. After at least one contact is saved, you can leave blank to finish.
        `);

        // Prompt for contacts (at least one required)
        const userContacts = {};

        while (true) {
            const excludeAccounts = [
                userName,
            ];
            const contact = promptUserInputReadline(
                `Contact's account name: `,
                (input) => input === "" || validateAccountNameStructure(input), // Allow empty input (if at least one contact is provided)
                false,
                null,
                0,
                excludeAccounts,
            );

            if (!contact && Object.keys(userContacts).length > 0) break; // Stop if input is empty and at least one contact was already provided

            if (!contact && Object.keys(userContacts).length === 0) {
                console.error(`Error: You must register at least one contact. Try again.`);
                continue;
            }

            if (userContacts.hasOwnProperty(contact)) {
                console.error(`Error: Contact ${contact} was already added. Try again.`);
                continue;
            }

            if (contact) {

                const opIndexInput = promptUserInputReadline(
                    `
    If you want, you can set an "operation index seen" number for this contact, so that only operations newer than that will be searched; this makes the first search for incoming messages much quicker, especially for contacts with extensive account history.

    Alternatively, you can choose to set this number as that of the oldest operation in a single "query batch" for this contact; this is likely the best option for most users.

    Enter the desired "operation index seen" number, or leave empty to get onchain the recommended number: `,
                    (input) => input === "" || /^([1-9]\d*|0)$/.test(input), // Empty input, or non-negative integer (zero allowed), no leading zeroes allowed
                );

                const opIndexSeen = await testOpIndexSeen(
                    contact,
                    opIndexInput, // string, can be empty
                    RPCs.map(([str]) => str), // flat array of strings
                );

                userContacts[contact] = {
                    op_index_seen: opIndexSeen,
                };

                console.log(`Contact ${contact} added successfully, with "operation index seen": ${opIndexSeen}`);
            }
        }

        // Build the "mail" object
        const mail = {
            memo_keys: privMemoKeys,
            pq_keys: privPQkeys,
            contacts: userContacts,
            messages_saved: [],
        };

        // Build the "accounts" object
        const accounts = {
            [userName]: {
                user_flags: {},
                posting_key: privPostingKey.slice(1),
                mail,
            }
        };

        // Build save file structure
        const saveFileContents = {
            global_flags: { mode: "ჰ0" },
            nodes: RPCs,
            accounts,
        };

        // Save
        await doSaveFile(saveFilePassw, saveFilePIN, saveFileContents, saveDir, saveFilePath);

        console.log(`
    New save file created successfully.
        `);

    } catch (err) {
        console.error(`Failed to create a new save file. Error: ${err.message}`);
        return;
        // throw err;
    }
}




