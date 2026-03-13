import {
    VARS,
} from "./state.js";
import {
    getHs,
} from "./hasher.js";
import {
    processFileUpload,
    saveToFile,
} from "./file.js";
import {
    bytesToUtf8,
    stripOuterQuotes,
} from "./utils.js";
import {
    valStringCharSet,
} from "./val.js";
import {
    base87CharSet,
} from "./charsets.js";
import {
    decBase87,
} from "./base87.js";
import {
    valAccName,
} from "./val-h.js";
import {
    decryptMsg,
} from "./hm-decrypt.js";

await getHs();

const addresseeInput = document.getElementById("addresseeDec");
const inputCont = document.getElementById("inputContDec");
const ciphertextInput = document.getElementById("ciphertextDec");
const fileInput = document.getElementById("fileInputDec");
const privKeyInput = document.getElementById("privKeyDec");
const decryptButton = document.getElementById("decryptButton");
const resultMessage = document.getElementById("resultMessageDec");
const copyButtonContainer = document.getElementById("copyButtonContainerDec");
const copyButton = document.getElementById("copyButtonDec");
const downloadButtonContainer = document.getElementById("downloadButtonContainerDec");
const downloadButton = document.getElementById("downloadButtonDec");

function clearOuts() {
    VARS[1] = null;
    copyButtonContainer.classList.remove("visible");
    copyButton.disabled = true;
    copyButton.style.backgroundColor = "";
    downloadButtonContainer.classList.remove("visible");
    downloadButton.disabled = true;
    downloadButton.style.backgroundColor = "";
}

fileInput.addEventListener("change", async e => {
    const file = e.target.files[0];
    let fileBytes;
    if (file) { fileBytes = await processFileUpload(file); }
    if (fileBytes) {
        ciphertextInput.value = "";
        ciphertextInput.style.borderColor = "";
        fileInput.value = "";
        VARS[0] = fileBytes;
        valDecryptButton();
        resultMessage.style.color = "lightblue";
        resultMessage.textContent = `File loaded successfully: ${file.name} (${VARS[0].length.toLocaleString()} bytes)`;
    } else {
        VARS[0] = null;
        fileInput.value = "";
        clearOuts();
        valDecryptButton();
        resultMessage.style.color = "red";
        resultMessage.textContent = "Error reading file!";
    }
});

function valCiphertext(input) {
    return typeof input === "string"
        && input.length > 65
        && valStringCharSet(stripOuterQuotes(input), base87CharSet);
}

function valPriv(input) {
    return typeof input === "string"
        && input.length > 13000
        && valStringCharSet(input, base87CharSet);
}

function valDecryptButton() {
    if (
        valAccName(addresseeInput.value.trim())
        && valPriv(privKeyInput.value.trim())
        && VARS?.length
        && (
            valCiphertext(ciphertextInput.value.trim())
            || (
                VARS[0] instanceof Uint8Array
                && VARS[0].length
            )
        )
    ) {
        decryptButton.disabled = false;
        decryptButton.style.backgroundColor = "green";

    } else {
        decryptButton.disabled = true;
        decryptButton.style.backgroundColor = "";
        resultMessage.textContent = "";
    }
}

addresseeInput.addEventListener("input", () => {
    const t = addresseeInput.value.trim();
    addresseeInput.style.borderColor = !t ? "" : valAccName(t) ? "green" : "red";
});
addresseeInput.addEventListener("input", valDecryptButton);

ciphertextInput.addEventListener("input", () => {
    const c = ciphertextInput.value.trim();
    const test = valCiphertext(c);
    ciphertextInput.style.borderColor = !c ? "" : test ? "green" : "red";
    if (test) {
        VARS[0] = null;
    }
});
ciphertextInput.addEventListener("input", valDecryptButton);

privKeyInput.addEventListener("input", () => {
    const k = privKeyInput.value.trim();
    privKeyInput.style.borderColor = !k ? "" : valPriv(k) ? "green" : "red";
});
privKeyInput.addEventListener("input", valDecryptButton);

decryptButton.addEventListener("click", async () => {
    const privKey = decBase87(privKeyInput.value.trim());
    privKeyInput.value = "";
    privKeyInput.style.borderColor = "";
    decryptButton.disabled = true;
    decryptButton.style.backgroundColor = "";

    const payloadStr = ciphertextInput.value.trim();
    let payload;
    if (
        valCiphertext(payloadStr)
    ) {
        payload = decBase87(stripOuterQuotes(payloadStr));
    } else if (
        VARS[0] instanceof Uint8Array
        && VARS[0].length
    ) {
        payload = VARS[0];
    } else {
        clearOuts();
        resultMessage.style.color = "red";
        resultMessage.textContent = `Invalid payload!`;
        return;
    }

    const [decrypted, inputIsFile] = await decryptMsg(
        addresseeInput.value.trim(),
        privKey,
        payload,
    );

    if (
        !(decrypted instanceof Uint8Array)
        || !decrypted.length
        || typeof inputIsFile !== "boolean"
    ) {
        clearOuts();
        resultMessage.style.color = "red";
        resultMessage.textContent = `Decryption failed!`;
        return;
    }

    if (inputIsFile) {
        copyButtonContainer.classList.remove("visible");
        copyButton.disabled = true;
        copyButton.style.backgroundColor = "";
        resultMessage.style.color = "green";
        resultMessage.textContent = `File successfully decrypted!`;
        downloadButtonContainer.classList.add("visible");
        downloadButton.disabled = false;
        downloadButton.style.backgroundColor = "darkorange";
        VARS[1] = decrypted;

    } else {
        downloadButtonContainer.classList.remove("visible");
        downloadButton.disabled = true;
        downloadButton.style.backgroundColor = "";
        const decryptedStr = bytesToUtf8(decrypted);

        if (
            typeof decryptedStr === "string"
            && decryptedStr.trim()
        ) {
            resultMessage.style.color = "green";
            resultMessage.textContent = `Message successfully decrypted!`;
            copyButtonContainer.classList.add("visible");
            copyButton.disabled = false;
            copyButton.style.backgroundColor = "darkorange";
            VARS[1] = decryptedStr;

        } else {
            clearOuts();
            resultMessage.style.color = "red";
            resultMessage.textContent = `Failed to decrypt message.`;
        }
    }
});

copyButton.addEventListener("click", () => {
    navigator.clipboard.writeText(VARS[1])
    .then(() => {
        copyButton.textContent = "Copied!";
        setTimeout(() => copyButton.textContent = "Copy the Decrypted Message", 5000);
    });
});

downloadButton.addEventListener("click", async () => {
    try {
        await saveToFile(VARS[1], "retrieved_file");

    } catch (err) {
        console.error(`
    Error in save flow!
${err && err.message ? err.message : err}
`);

        alert("Failed to save the retrieved file: " + (err && err.message ? err.message : err));
    }

    downloadButton.textContent = "Downloaded!";
    setTimeout(() => {
        downloadButton.textContent = `Download the Retrieved File`;
    }, 5000);
});
