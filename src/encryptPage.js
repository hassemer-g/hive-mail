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
    utf8ToBytes,
} from "./utils.js";
import {
    encBase87,
} from "./base87.js";

import {
    NODES,
    getRespNodes,
} from "./rpcs.js";
import {
    valAccName,
} from "./val-h.js";
import {
    fetchPubKey,
} from "./hm-pubkeys.js";
import {
    encryptMsg,
} from "./hm-encrypt.js";

await getRespNodes();
await getHs();

const resultMessage = document.getElementById("resultMessageEnc");

if (!NODES?.length) {
    resultMessage.textContent = `Hive RPCs unresponsive! Try again later...`;
    resultMessage.style.color = "red";
}

const addresseeInput = document.getElementById("addresseeEnc");

const inputCont = document.getElementById("inputContEnc");
const plaintextInput = document.getElementById("plaintextEnc");
const fileInput = document.getElementById("fileInputEnc");
const useKyber = document.getElementById("useKyber");
const useHQC = document.getElementById("useHQC");
const encryptButton = document.getElementById("encryptButton");
const outButtonsContainer = document.getElementById("outButtonsContainerEnc");

const copyButton = document.getElementById("copyButtonEnc");
const downloadButton = document.getElementById("downloadButtonEnc");

fileInput.addEventListener("change", async e => {
    const file = e.target.files[0];
    let fileBytes;
    if (file) { fileBytes = await processFileUpload(file); }
    if (fileBytes) {
        plaintextInput.value = "";
        plaintextInput.style.borderColor = "";
        fileInput.value = "";
        VARS[0] = fileBytes;
        valEncryptButton();
        resultMessage.style.color = "lightblue";
        resultMessage.textContent = `File loaded successfully: ${file.name} (${VARS[0].length.toLocaleString()} bytes)`;
    } else {
        VARS[0] = null;
        fileInput.value = "";
        outButtonsContainer.classList.remove("visible");

        copyButton.disabled = true;
        copyButton.style.backgroundColor = "";
        downloadButton.disabled = true;
        downloadButton.style.backgroundColor = "";
        valEncryptButton();
        resultMessage.style.color = "red";
        resultMessage.textContent = "Error reading file!";
    }
});

function valEncryptButton() {
    const p = plaintextInput.value.trim();
    if (
        valAccName(addresseeInput.value.trim())
        && NODES?.length
        && VARS?.length
        && (
            (
                typeof p === "string"
                && p.trim()
            )
            || (
                VARS[0] instanceof Uint8Array
                && VARS[0].length
            )
        )
    ) {
        encryptButton.disabled = false;
        encryptButton.style.backgroundColor = "green";
    } else {
        encryptButton.disabled = true;
        encryptButton.style.backgroundColor = "";
        outButtonsContainer.classList.remove("visible");

        copyButton.disabled = true;
        copyButton.style.backgroundColor = "";
        downloadButton.disabled = true;
        downloadButton.style.backgroundColor = "";
        VARS[1] = null;
        if (NODES?.length) { resultMessage.textContent = ""; }
    }
}

addresseeInput.addEventListener("input", () => {
    const t = addresseeInput.value.trim();
    addresseeInput.style.borderColor = !t ? "" : valAccName(t) ? "green" : "red";
});
addresseeInput.addEventListener("input", valEncryptButton);

plaintextInput.addEventListener("input", () => {
    const p = plaintextInput.value.trim();
    const test = typeof p === "string" && p.length;
    plaintextInput.style.borderColor = !p ? "" : test ? "green" : "red";
    if (test) {
        VARS[0] = null;
    }
});
plaintextInput.addEventListener("input", valEncryptButton);

useKyber.addEventListener("change", () => {
        outButtonsContainer.classList.remove("visible");

        copyButton.disabled = true;
        copyButton.style.backgroundColor = "";
        downloadButton.disabled = true;
        downloadButton.style.backgroundColor = "";
        resultMessage.textContent = "";
        VARS[1] = null;
});

useHQC.addEventListener("change", () => {
        outButtonsContainer.classList.remove("visible");

        copyButton.disabled = true;
        copyButton.style.backgroundColor = "";
        downloadButton.disabled = true;
        downloadButton.style.backgroundColor = "";
        resultMessage.textContent = "";
        VARS[1] = null;
});

encryptButton.addEventListener("click", async () => {
    const addressee = addresseeInput.value.trim();

    let recipientPubHMkey;
    try {

        [recipientPubHMkey] = await fetchPubKey(
            addressee,
            NODES,
        );
    } catch (err) {
        resultMessage.textContent = `Failed to get the metadata from account "${addressee}"!`;
        resultMessage.style.color = "red";
        return;
    }

    if (
        !(recipientPubHMkey instanceof Uint8Array)
        || !recipientPubHMkey.length
    ) {
        resultMessage.textContent = `Failed to get the Hive-Mail Public Key from the onchain metada of account "${addressee}"`;
        resultMessage.style.color = "red";
    }

    let plaintext, inputIsFile;
    if (
        VARS[0] instanceof Uint8Array
        && VARS[0].length
    ) {
        plaintext = VARS[0];
        inputIsFile = true;

    } else {
        plaintext = plaintextInput.value.trim();
        inputIsFile = false;
    }

    const encrypted = await encryptMsg(
        inputIsFile ? plaintext : utf8ToBytes(plaintext),
        addressee,
        recipientPubHMkey,

        useKyber.checked,
        useHQC.checked,
        inputIsFile,
    );

    if (
        !(encrypted instanceof Uint8Array)
        || !encrypted.length
    ) {
        resultMessage.textContent = `Failed to encrypt message!`;
        resultMessage.style.color = "red";
    }

    resultMessage.textContent = `Message successfully encrypted!`;
    resultMessage.style.color = "green";
    outButtonsContainer.classList.add("visible");

    copyButton.disabled = false;
    copyButton.style.backgroundColor = "darkorange";
    downloadButton.disabled = false;
    downloadButton.style.backgroundColor = "darkorange";
    VARS[1] = encrypted;
});

copyButton.addEventListener("click", () => {
    navigator.clipboard.writeText(`"` + encBase87(VARS[1]) + `"`)
    .then(() => {
        copyButton.textContent = "Copied!";
        setTimeout(() => copyButton.textContent = `Copy the Encrypted Output as a String`, 5000);
    });
});

downloadButton.addEventListener("click", async () => {
    try {

        await saveToFile(VARS[1], "encrypted");

    } catch (err) {
        console.error(`
    Error in save flow!
${err && err.message ? err.message : err}
`);

        alert("Failed to save the encrypted output as a file: " + (err && err.message ? err.message : err));
    }

    downloadButton.textContent = "Downloaded!";
    setTimeout(() => {
        downloadButton.textContent = `Download the Encrypted Output as a File`;
    }, 5000);
});
