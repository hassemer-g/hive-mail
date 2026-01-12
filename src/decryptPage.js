import {
    createSHA512,
    createSHA3,
    createWhirlpool,
    createBLAKE2b,
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
    decodeBase91,
} from "./base91.js";
import {
    valAccountNameStructure,
} from "./val-h.js";
import {
    decryptMsg,
} from "./hm-decrypt.js";

const Hs = [
    await createSHA3(),
    await createBLAKE2b(),
    await createSHA512(),
    await createWhirlpool(),
];

const addresseeDecInput = document.getElementById("addresseeDec");
const ciphertextDecInput = document.getElementById("ciphertextDec");
const privKeyDecInput = document.getElementById("privKeyDec");
const decryptButton = document.getElementById("decryptButton");
const resultMessageDec = document.getElementById("resultMessageDec");
const copyButtonDec = document.getElementById("copyButtonDec");

let DECRYPTED_MSG = null;

function valCiphertext(input) {
    if (typeof input !== "string") return false;
    return input.startsWith(`"`) && input.endsWith(`"`) && input.length > 66;
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
    const privKey = privKeyDecInput.value.trim();

    privKeyDecInput.value = "";
    privKeyDecInput.style.borderColor = "";
    decryptButton.disabled = true;
    decryptButton.style.backgroundColor = "";

    const payloadStr = ciphertextDecInput.value.trim();

    if (
        !payloadStr.startsWith(`"`)
        || !payloadStr.endsWith(`"`)
        || !valStringCharSet(payloadStr.slice(1, -1), customBase91CharSet)
    ) {
        resultMessageDec.textContent = `Invalid ciphertext input!`;
        resultMessageDec.style.color = "red";
        return;
    }

    try {

        const [decrypted, inputIsFile] = await decryptMsg(
            addresseeDecInput.value.trim(),
            decodeBase91(privKey.slice(1, -1)),
            decodeBase91(payloadStr.slice(1, -1)),
            Hs,
        );

        let decryptedStr;
        if (!inputIsFile) { decryptedStr = bytesToUtf8(decrypted); }

        if (
            decryptedStr
            && typeof decryptedStr === "string"
        ) {
            resultMessageDec.textContent = `Message successfully decrypted!`;
            resultMessageDec.style.color = "green";
            copyButtonDec.disabled = false;
            copyButtonDec.style.backgroundColor = "darkorange";
            DECRYPTED_MSG = decryptedStr;

        } else {
            DECRYPTED_MSG = null;
            resultMessageDec.textContent = `Failed to decrypt message!`;
            resultMessageDec.style.color = "red";
        }

    } catch (err) {
        DECRYPTED_MSG = null;
        resultMessageDec.textContent = `Failed to decrypt message!`;
        resultMessageDec.style.color = "red";
    }
});

copyButtonDec.addEventListener("click", () => {
    navigator.clipboard.writeText(DECRYPTED_MSG)
    .then(() => {
        copyButtonDec.textContent = "Copied!";
        setTimeout(() => copyButtonDec.textContent = "Copy the Decrypted Message", 5000);
    });
});
