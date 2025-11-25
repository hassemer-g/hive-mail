import {
    createSHA512,
    createSHA3,
    createWhirlpool,
    createBLAKE2b,
    createBLAKE3,
    createSM3,
} from "./hash-wasm/hash-wasm.mjs";
import {
    bytesToUtf8,
} from "./utils.js";
import {
    valStringCharSet,
} from "./val.js";
import {
    customBase91CharSet,
} from "./charsets.js";
import {
    encodeBase91,
    decodeBase91,
} from "./base91.js";
import {
    valAccountNameStructure,
} from "./val-h.js";
import {
    decryptMsg,
} from "./hm-decrypt.js";

const Hs = {
    sha2: await createSHA512(),
    sha3: await createSHA3(),
    whirlpool: await createWhirlpool(),
    blake2: await createBLAKE2b(),
    blake3: await createBLAKE3(),
    sm3: await createSM3(),
};

const addresseeDecInput = document.getElementById("addresseeDec");
const ciphertextDecInput = document.getElementById("ciphertextDec");
const privKeyDecInput = document.getElementById("privKeyDec");
const decryptButton = document.getElementById("decryptButton");
const resultMessageDec = document.getElementById("resultMessageDec");
const copyButtonDec = document.getElementById("copyButtonDec");

let DECRYPTED_MSG = null;

function valCiphertext(input) {
    if (typeof input !== "string") return false;
    return input.startsWith(`"`) && input.endsWith(`"`) && input.length > 60;
}

function valPriv(input) {
    if (typeof input !== "string") return false;
    return input.startsWith(`"`) && input.endsWith(`"`) && input.length > 12900;
}

function valDecryptButton() {

    if (
        valAccountNameStructure(addresseeDecInput.value.trim())
        && valCiphertext(ciphertextDecInput.value.trim())
        && valPriv(privKeyDecInput.value.trim())
    ) {
        decryptButton.disabled = false;
        decryptButton.style.backgroundColor = "green";
    } else {

        decryptButton.disabled = true;
        decryptButton.style.backgroundColor = "";
        resultMessageDec.textContent = "";

    }
}

addresseeDecInput.addEventListener("input", () => {
    const t = addresseeDecInput.value.trim();
    addresseeDecInput.style.borderColor = !t ? "" : valAccountNameStructure(t) ? "green" : "red";
});
addresseeDecInput.addEventListener("input", valDecryptButton);

ciphertextDecInput.addEventListener("input", () => {
    const c = ciphertextDecInput.value.trim();
    ciphertextDecInput.style.borderColor = !c ? "" : valCiphertext(c) ? "green" : "red";
});
ciphertextDecInput.addEventListener("input", valDecryptButton);

privKeyDecInput.addEventListener("input", () => {
    const k = privKeyDecInput.value.trim();
    privKeyDecInput.style.borderColor = !k ? "" : valPriv(k) ? "green" : "red";
});
privKeyDecInput.addEventListener("input", valDecryptButton);

decryptButton.addEventListener("click", async () => {

    const msgStr = ciphertextDecInput.value.trim();

    let payloadStr, doNotUsePq = false, usedFileEnc = false;
    if (msgStr.endsWith(`"`)) {
        if (msgStr.startsWith(`"0M"`)) {
            payloadStr = msgStr.slice(4, -1);
        } else if (msgStr.startsWith(`"0m"`)) {
            doNotUsePq = true;
            payloadStr = msgStr.slice(4, -1);
        } else if (msgStr.startsWith(`"0MF"`)) {
            usedFileEnc = true;
            payloadStr = msgStr.slice(5, -1);
        } else if (msgStr.startsWith(`"0mF"`)) {
            doNotUsePq = true;
            usedFileEnc = true;
            payloadStr = msgStr.slice(5, -1);
        } else {
            resultMessageDec.textContent = `Invalid ciphertext input!`;
            resultMessageDec.style.color = "red";
            privKeyDecInput.value = "";
            privKeyDecInput.style.borderColor = "";
            decryptButton.disabled = true;
            decryptButton.style.backgroundColor = "";
            return;
        }
    } else {
        resultMessageDec.textContent = `Invalid ciphertext input!`;
        resultMessageDec.style.color = "red";
        privKeyDecInput.value = "";
        privKeyDecInput.style.borderColor = "";
        decryptButton.disabled = true;
        decryptButton.style.backgroundColor = "";
        return;
    }

    if (
        !valStringCharSet(payloadStr, customBase91CharSet)
    ) {
        resultMessageDec.textContent = `Invalid ciphertext input! Payload is not Base91 encoded.`;
        resultMessageDec.style.color = "red";
        privKeyDecInput.value = "";
        privKeyDecInput.style.borderColor = "";
        decryptButton.disabled = true;
        decryptButton.style.backgroundColor = "";
        return;
    }

    try {

        const decrypted = await decryptMsg(
            addresseeDecInput.value.trim(),
            decodeBase91(privKeyDecInput.value.trim().slice(1, -1)),
            decodeBase91(payloadStr),
            Hs,
            doNotUsePq,
        );

        let decryptedStr;
        if (usedFileEnc) {
            decryptedStr = `"F"${encodeBase91(decrypted)}"`;
        } else {
            decryptedStr = bytesToUtf8(decrypted);
        }

        if (
            decryptedStr
            && typeof decryptedStr === "string"
        ) {

            resultMessageDec.textContent = `Message successfully decrypted!`;
            resultMessageDec.style.color = "green";
            copyButtonDec.disabled = false;
            copyButtonDec.style.backgroundColor = "darkorange";
            DECRYPTED_MSG = decryptedStr;
            privKeyDecInput.value = "";
            privKeyDecInput.style.borderColor = "";
            decryptButton.disabled = true;
            decryptButton.style.backgroundColor = "";

        } else {

            DECRYPTED_MSG = null;
            resultMessageDec.textContent = `Failed to decrypt message!`;
            resultMessageDec.style.color = "red";
            privKeyDecInput.value = "";
            privKeyDecInput.style.borderColor = "";
            decryptButton.disabled = true;
            decryptButton.style.backgroundColor = "";
        }

    } catch (err) {
        DECRYPTED_MSG = null;
        resultMessageDec.textContent = `Failed to decrypt message! Error: ${err.message}`;
        resultMessageDec.style.color = "red";
        privKeyDecInput.value = "";
        privKeyDecInput.style.borderColor = "";
        decryptButton.disabled = true;
        decryptButton.style.backgroundColor = "";
    }
});

copyButtonDec.addEventListener("click", () => {
    navigator.clipboard.writeText(DECRYPTED_MSG)
    .then(() => {
        copyButtonDec.textContent = "Copied!";
        setTimeout(() => copyButtonDec.textContent = "Copy the Decrypted Message", 5000);
    });
});
