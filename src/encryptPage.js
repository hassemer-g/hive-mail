import {
    createSHA512,
    createSHA3,
    createBLAKE2b,
    createBLAKE3,
    createWhirlpool,
    createXXHash128,
} from "./hash-wasm/hash-wasm.mjs";
import { RPCsArray } from "./rpcs.js";
import { testRPCsWithDhive } from "./test_rpcs.js";
import {
    valAccountNameStructure,
} from "./val-h.js";
import {
    fetchPubKey,
} from "./hm-pubkeys.js";
import {
    encryptMsg,
} from "./hm-encrypt.js";

const testedRPCs = await testRPCsWithDhive(RPCsArray);
console.log("testedRPCs: ", testedRPCs);

const resultMessage = document.getElementById("resultMessageEnc");

if (!testedRPCs || !testedRPCs.length) {
    resultMessage.textContent = `All Hive RPCs are unresponsive! Try again later...`;
    resultMessage.style.color = "red";
}

const Hs = {
    sha2: await createSHA512(),
    sha3: await createSHA3(),
    blake2: await createBLAKE2b(),
    blake3: await createBLAKE3(),
    whirlpool: await createWhirlpool(),
    xxhash: await createXXHash128(),
};

const addresseeInput = document.getElementById("addresseeEnc");
const plaintextInput = document.getElementById("plaintextEnc");
const encryptButton = document.getElementById("encryptButton");
const copyButtonEnc = document.getElementById("copyButtonEnc");

let ENCRYPTED_MSG = null;

function valEncryptButton() {

    if (
        valAccountNameStructure(addresseeInput.value.trim())
        && typeof plaintextInput.value.trim() === "string"
        && plaintextInput.value.trim().length > 0
        && testedRPCs.length
    ) {
        encryptButton.disabled = false;
        encryptButton.style.backgroundColor = "green";
    } else {
        encryptButton.disabled = true;
        encryptButton.style.backgroundColor = "";
        copyButtonEnc.disabled = true;
        copyButtonEnc.style.backgroundColor = "";
        resultMessage.textContent = "";
        ENCRYPTED_MSG = null;
    }
}

addresseeInput.addEventListener("input", () => {
    const isValid = valAccountNameStructure(addresseeInput.value.trim());
    addresseeInput.style.borderColor = isValid ? "green" : "red";
});
addresseeInput.addEventListener("input", valEncryptButton);

plaintextInput.addEventListener("input", () => {
    const isValid = typeof plaintextInput.value.trim() === "string" && plaintextInput.value.trim().length > 0;
    plaintextInput.style.borderColor = isValid ? "green" : "red";
});
plaintextInput.addEventListener("input", valEncryptButton);

encryptButton.addEventListener("click", async () => {

    let recipientPubHMkey = null;
    try {

        recipientPubHMkey = await fetchPubKey(
            addresseeInput.value.trim(),
            testedRPCs,
        );
    } catch (err) {
        resultMessage.textContent = `Failed to get the metadata from account "${addresseeInput.value.trim()}"!`;
        resultMessage.style.color = "red";
    }

    if (recipientPubHMkey && recipientPubHMkey instanceof Uint8Array) {

        const msgStr = await encryptMsg(
            plaintextInput.value.trim(),
            addresseeInput.value.trim(),
            recipientPubHMkey,
            Hs,
        );

        if (
            typeof msgStr === "string" && msgStr.trim()
        ) {

        resultMessage.textContent = `Message successfully encrypted!`;
        resultMessage.style.color = "green";
        copyButtonEnc.disabled = false;
        copyButtonEnc.style.backgroundColor = "darkorange";
        ENCRYPTED_MSG = `"${msgStr}"`;

        } else {
            resultMessage.textContent = `Failed to encrypt message!`;
            resultMessage.style.color = "red";
        }
    } else {
        resultMessage.textContent = `The account ${addresseeInput.value.trim()} does not have a Hive-Mail public key registered onchain!`;
        resultMessage.style.color = "red";
    }
});

copyButtonEnc.addEventListener("click", () => {
    navigator.clipboard.writeText(ENCRYPTED_MSG)
    .then(() => {
        copyButtonEnc.textContent = "Copied!";
        setTimeout(() => copyButtonEnc.textContent = "Copy the Encrypted Message", 5000);
    });
});

valEncryptButton();
