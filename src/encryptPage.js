import {
    createSHA512,
    createSHA3,
    createWhirlpool,
    createBLAKE2b,
    createBLAKE3,
    createSM3,
} from "./hash-wasm/hash-wasm.mjs";
import {
    utf8ToBytes,
} from "./utils.js";
import {
    encodeBase91,
    decodeBase91,
} from "./base91.js";
import {
    customBase91CharSet,
} from "./charsets.js";
import { valStringCharSet } from "./val.js";
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

const resultMessage = document.getElementById("resultMessageEnc");

if (!testedRPCs || !testedRPCs.length) {
    resultMessage.textContent = `All Hive RPCs are unresponsive! Try again later...`;
    resultMessage.style.color = "red";
}

const Hs = {
    sha2: await createSHA512(),
    sha3: await createSHA3(),
    whirlpool: await createWhirlpool(),
    blake2: await createBLAKE2b(),
    blake3: await createBLAKE3(),
    sm3: await createSM3(),
};

const addresseeInput = document.getElementById("addresseeEnc");
const plaintextInput = document.getElementById("plaintextEnc");
const usePQ = document.getElementById("usePQ");
const encryptButton = document.getElementById("encryptButton");
const copyButtonEnc = document.getElementById("copyButtonEnc");

let ENCRYPTED_MSG = null;

function valEncryptButton() {

    const p = plaintextInput.value.trim();

    if (
        valAccountNameStructure(addresseeInput.value.trim())
        && typeof p === "string"
        && p.length
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
    const t = addresseeInput.value.trim();
    addresseeInput.style.borderColor = !t ? "" : valAccountNameStructure(t) ? "green" : "red";
});
addresseeInput.addEventListener("input", valEncryptButton);

plaintextInput.addEventListener("input", () => {
    const p = plaintextInput.value.trim();
    plaintextInput.style.borderColor = !p ? "" : (typeof p === "string" && p.length) ? "green" : "red";
});
plaintextInput.addEventListener("input", valEncryptButton);

usePQ.addEventListener("change", () => {
        copyButtonEnc.disabled = true;
        copyButtonEnc.style.backgroundColor = "";
        resultMessage.textContent = "";
        ENCRYPTED_MSG = null;
});

encryptButton.addEventListener("click", async () => {

    const addressee = addresseeInput.value.trim();

    let recipientPubHMkey;
    try {

        recipientPubHMkey = await fetchPubKey(
            addressee,
            testedRPCs,
        );
    } catch (err) {
        resultMessage.textContent = `Failed to get the metadata from account "${addressee}"!`;
        resultMessage.style.color = "red";
        return;
    }

    if (recipientPubHMkey && recipientPubHMkey instanceof Uint8Array && recipientPubHMkey.length) {

        const plaintext = plaintextInput.value.trim();
        let plaintextBytes, fileEncInput = false;
        if (
            plaintext.startsWith(`"F"`)
            && plaintext.endsWith(`"`)
            && valStringCharSet(plaintext.slice(3, -1), customBase91CharSet)
        ) {
            plaintextBytes = decodeBase91(plaintext.slice(3, -1));
            fileEncInput = true;
        } else {
            plaintextBytes = utf8ToBytes(plaintext);
        }

        const toUsePq = usePQ.checked;

        const payload = await encryptMsg(
            plaintextBytes,
            addressee,
            recipientPubHMkey,
            Hs,
            toUsePq ? false : true,
        );

        let msgStr;
        if (fileEncInput) {
            if (toUsePq) {
                msgStr = `"0MF"${encodeBase91(payload)}"`;
            } else {
                msgStr = `"0mF"${encodeBase91(payload)}"`;
            }
        } else {
            if (toUsePq) {
                msgStr = `"0M"${encodeBase91(payload)}"`;
            } else {
                msgStr = `"0m"${encodeBase91(payload)}"`;
            }
        }

        if (
            typeof msgStr === "string"
            && msgStr.trim()
        ) {

        resultMessage.textContent = `Message successfully encrypted!`;
        resultMessage.style.color = "green";
        copyButtonEnc.disabled = false;
        copyButtonEnc.style.backgroundColor = "darkorange";
        ENCRYPTED_MSG = msgStr;

        } else {
            resultMessage.textContent = `Failed to encrypt message!`;
            resultMessage.style.color = "red";
        }
    } else {
        resultMessage.textContent = `The account ${addressee} does not have a Hive-Mail public key registered onchain!`;
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
