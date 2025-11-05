import {
    createSHA512,
    createSHA3,
    createBLAKE2b,
    createBLAKE3,
    createWhirlpool,
    createXXHash128,
} from "./hash-wasm/hash-wasm.mjs";
import {
    valStringCharSet,
} from "./val.js";
import {
    customBase91CharSet,
} from "./charsets.js";
import {
    decodeBase91,
} from "./base91.js";
import {
    bytesToInteger,
} from "./numbers.js";
import {
    valAccountNameStructure,
} from "./val-h.js";
import {
    decryptMsg,
} from "./hm-decrypt.js";

const Hs = {
    sha2: await createSHA512(),
    sha3: await createSHA3(),
    blake2: await createBLAKE2b(),
    blake3: await createBLAKE3(),
    whirlpool: await createWhirlpool(),
    xxhash: await createXXHash128(),
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
    return input.startsWith('"') && input.endsWith('"') && input.length > 70;
}

function valPriv(input) {
    if (typeof input !== "string") return false;
    return input.startsWith('"') && input.endsWith('"') && input.length > 12900;
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
    const isValid = valAccountNameStructure(addresseeDecInput.value.trim());
    addresseeDecInput.style.borderColor = isValid ? "green" : "red";
});
addresseeDecInput.addEventListener("input", valDecryptButton);

ciphertextDecInput.addEventListener("input", () => {
    const isValid = valCiphertext(ciphertextDecInput.value.trim());
    ciphertextDecInput.style.borderColor = isValid ? "green" : "red";
});
ciphertextDecInput.addEventListener("input", valDecryptButton);

privKeyDecInput.addEventListener("input", () => {
    const isValid = valPriv(privKeyDecInput.value.trim());
    privKeyDecInput.style.borderColor = isValid ? "green" : "red";
});
privKeyDecInput.addEventListener("input", valDecryptButton);

decryptButton.addEventListener("click", async () => {

    const cleanedMsgStr = ciphertextDecInput.value.trim().slice(1, -1);

    let doNotUsePq;
    if (cleanedMsgStr.startsWith("0M")) {
        doNotUsePq = false;
    } else if (cleanedMsgStr.startsWith("0m")) {
        doNotUsePq = true;
    } else {
        resultMessageDec.textContent = `Invalid ciphertext input!`;
        resultMessageDec.style.color = "red";
        return;
    }

    const payloadStr = cleanedMsgStr.slice(2);

    if (
        !valStringCharSet(payloadStr, customBase91CharSet)
    ) {
        resultMessageDec.textContent = `Invalid ciphertext input! Content is not Base91 encoded.`;
        resultMessageDec.style.color = "red";
        return;
    }

    const timestamp = bytesToInteger(decodeBase91(timestampStr));

    const decrypted = await decryptMsg(
        addresseeDecInput.value.trim(),
        decodeBase91(privKeyDecInput.value.trim().slice(1, -1)),
        decodeBase91(payloadStr),
        Hs,
        doNotUsePq,
    );

    if (
        decrypted && typeof decrypted === "string"
    ) {

    resultMessageDec.textContent = `Message successfully decrypted!`;
    resultMessageDec.style.color = "green";
    copyButtonDec.disabled = false;
    copyButtonDec.style.backgroundColor = "darkorange";
    DECRYPTED_MSG = decrypted;

    } else {
        resultMessageDec.textContent = `Failed to decrypt message!`;
        resultMessageDec.style.color = "red";
    }

    privKeyDecInput.value = "";
    privKeyDecInput.style.borderColor = "";
    decryptButton.disabled = true;
    decryptButton.style.backgroundColor = "";
});

copyButtonDec.addEventListener("click", () => {
    navigator.clipboard.writeText(DECRYPTED_MSG)
    .then(() => {
        copyButtonDec.textContent = "Copied!";
        setTimeout(() => copyButtonDec.textContent = "Copy the Decrypted Message", 5000);
    });
});


