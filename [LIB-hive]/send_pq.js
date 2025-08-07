import bs58 from "bs58";
import {
    utf8ToBytes,
    randomBytes,
} from "@noble/hashes/utils";
import pqclean from "pqclean";
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
    encryptXChaCha20Poly1305,
} from "../[LIB]/xchacha20_poly1305.js";

import { derivForMsg } from "./hm_deriv.js";
import {
    fetchLatestOpIndex,
} from "./async_aux_fxs.js";


// ==================================================================== //


// Broadcast encrypted message
export async function broadcastEncryptedMessage(
    senderName,
    senderPrivPostingKey, // string
    recipientName,
    recipientPubMemoKey, // string
    recipientPubPQkey, // string
    RPCs, // flat array of strings
    unencryptedMessageToSend,
) {

    try {

        // Get the operation index to be used for the encryption steps
        const opIndex = await fetchLatestOpIndex(senderName, RPCs) + 1;

        // Build transaction code
        const txCode = `${senderName}—${opIndex}—${recipientName}`;
        console.log(`Unique transaction code:`, txCode);

        // Obtain shared secret (Memo Key)
        const ephemeralPriv = PrivateKey.fromSeed(randomBytes(32));
        const memoPub = PublicKey.fromString(recipientPubMemoKey);
        const memoSharedSecret = new Uint8Array(ephemeralPriv.get_shared_secret(memoPub)); // Uint8Array, 64 bytes
        const memoEphemeral = bs58.decode(ephemeralPriv.createPublic().toString().slice(3)); // Uint8Array (after removal of the "STM" prefix), 37 bytes

        /*
        // Debugging
        console.log("\"memoEphemeral\", in Base58:", bs58.encode(memoEphemeral));
        console.log("\"memoEphemeral\" byte length:", memoEphemeral.length);
        console.log("\"memoSharedSecret\", in Base91:", bytesToBase91(memoSharedSecret));
        console.log("\"memoSharedSecret\" byte length:", memoSharedSecret.length);
        */

        // Obtain shared secret (Post-Quantum Key)
        const pqPub = new pqclean.kem.PublicKey("ml-kem-1024", bytesFromBase91(recipientPubPQkey));
        const { key, encryptedKey } = await pqPub.generateKey();
        const pqSharedSecret = new Uint8Array(key); // Uint8Array, 32 bytes
        const pqEphemeral = new Uint8Array(encryptedKey); // Uint8Array, 1568 bytes

        /*
        // Debugging
        console.log("\"pqEphemeral\", in Base91:", bytesToBase91(pqEphemeral));
        console.log("\"pqEphemeral\" byte length:", pqEphemeral.length);
        console.log("\"pqSharedSecret\", in Base91:", bytesToBase91(pqSharedSecret));
        console.log("\"pqSharedSecret\" byte length:", pqSharedSecret.length);
        */

        // Build and derive required keys, nonces, passwords and salts (returns all in Uint8Array)
        const { keyForEncrypt, nonceForEncrypt } = derivForMsg(
            txCode, // string
            recipientPubMemoKey.slice(3), // string (removed of the "STM" prefix)
            recipientPubPQkey, // string
            memoSharedSecret, // Uint8Array, 64 bytes
            pqSharedSecret, // Uint8Array, 32 bytes
        );

        // Perform symmetric encryption (returns Uint8Array)
        const ciphertext = encryptXChaCha20Poly1305(
            utf8ToBytes(unencryptedMessageToSend), // Uint8Array
            keyForEncrypt, // Uint8Array
            nonceForEncrypt, // Uint8Array
        );
        console.log("Output from symmetric encryption (Base91):", bytesToBase91(ciphertext));

        /*
        // Debugging
        console.log("\"ciphertext\" byte length:", ciphertext.length);
        */

        // Concatenate payload to be published
        const payload = new Uint8Array([
            ...memoEphemeral, // 37 bytes
            ...pqEphemeral, // 1568 bytes
            ...ciphertext,
        ]);

        const base91Payload = bytesToBase91(payload);
        console.log("Payload to be broadcast (Base91):", base91Payload);

        // Ensure input is a non-empty string
        if (typeof base91Payload !== "string" || base91Payload.trim() === "" || !(validateStringCharSet(base91Payload, customBase91CharSet))) {
            throw new Error(`Invalid payload to be broadcast.`);
        }

        // BROADCAST THE ENCRYPTED MESSAGE

        // Prepare the custom_json operation
        const op = [
            "custom_json", {
                id: "ჰ0",
                json: JSON.stringify({ მ: base91Payload }, null, 0),
                required_auths: [],
                required_posting_auths: [senderName],
            }
        ];

        console.log(`Prepared "custom_json" operation: ${JSON.stringify(op, null, 2)}`);

        // Sign and broadcast
        const signingKey = PrivateKey.fromString(senderPrivPostingKey);

        console.log(`Broadcasting transaction...`);

        const result = await new Client(shuffleArray(RPCs)).broadcast.sendOperations([op], signingKey);

        console.log(`Transaction successfully broadcast. Transaction ID: ${result.id}`);

        // Wait 2 seconds before attempting to fetch the transaction onchain
        await new Promise(resolve => setTimeout(resolve, 2000));

        // Get the complete transaction data
        let tx = null;
        while (!tx) {
            try {
                tx = await new Client(shuffleArray(RPCs)).call("condenser_api", "get_transaction", [result.id]);
                if (!tx) {
                    console.warn(`Transaction not found, retrying...`);
                    await new Promise(resolve => setTimeout(resolve, 1000));
                }
            } catch (err) {
                console.warn(`Error: ${err}. Transaction not found, retrying...`);
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        }

        /*
        // Debugging
        console.log(`Complete transaction info recovered:

        ${JSON.stringify(tx, null, 2)}
        `);
        */

        // Make sure the transaction does not include other operations
        if (tx.operations.length !== 1) {
            console.error(`Critical security warning: Broadcast transaction includes more than one operation.`);
            throw new Error(`Transaction includes more than one operation.`);
        }

        // Make sure data published onchain is exactly as intended
        if (JSON.stringify(tx.operations[0], null, 0) !== JSON.stringify(op, null, 0)) {
            console.error(`Critical warning: Data published onchain differs from that we provided. Your message was NOT published as intended!`);
            throw new Error(`Data published onchain does not match operation prepared by user.`);
        }

        console.log(`Transaction included in block: ${tx.block_num}`);

        // Fetch the block to get the timestamp
        let block = null;
        while (!block) {
            try {
                block = await new Client(shuffleArray(RPCs)).database.getBlock(tx.block_num);
                if (!block) {
                    console.warn(`Block not found, retrying...`);
                    await new Promise(resolve => setTimeout(resolve, 1000));
                }

            } catch (err) {
                console.error(`Error: ${err}. Block not found, retrying...`);
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        }

        // Store required info about successfully broadcast message
        const broadcastMessage = {
            block: tx.block_num,
            timestamp: block.timestamp,
            tx_id: result.id,
            sender: senderName,
            op_index: opIndex,
            addressee: recipientName,
            message: unencryptedMessageToSend,
            flags: {},
        };

        return broadcastMessage;

    } catch (err) {
        console.error("Failed to send encrypted message:", err.message);
        throw err;
    }
}


