import dhive from "./dhive/dhive.mjs";

import {
    shuffleArray,
} from "./utils.js";
import {
    encodeBase91,
    decodeBase91,
} from "./base91.js";
import { valStringCharSet } from "./val.js";
import {
    customBase91CharSet,
} from "./charsets.js";
import { RPCsArray } from "./rpcs.js";
import { testRPCsWithDhive } from "./test_rpcs.js";
import {
    valAccountNameStructure,
    valHivePrivKey,
} from "./val-h.js";
import {
    checkPubKeyOnchain,
    fetchPubKey,
} from "./hm-pubkeys.js";
import {
    createHMkeyPair,
    valHMpubKey,
} from "./hm-keys.js";

const testedRPCs = await testRPCsWithDhive(RPCsArray);
console.log("testedRPCs: ", testedRPCs);

const resultMessage1 = document.getElementById("resultMessage1Gen");

if (!testedRPCs || !testedRPCs.length) {
    resultMessage1.textContent = `All Hive RPCs are unresponsive! Try again later...`;
    resultMessage1.style.color = "red";
}

const accountNameInput = document.getElementById("accountNameGen");
const checkButton = document.getElementById("checkButtonGen");
const genButton = document.getElementById("genButtonGen");
const resultMsg2Cont = document.getElementById("resultMsg2GenContainer");
const resultMessage2 = document.getElementById("resultMessage2Gen");
const copyButtonGen = document.getElementById("copyButtonGen");
const confirmCheckboxContainer = document.getElementById("confirmCheckboxContainer");
const confirmSavedKey = document.getElementById("confirmSavedKey");
const keychainContainer = document.getElementById("keychainContainerGen");
const useHiveKeychain = document.getElementById("useHiveKeychainGen");
const privActiveKeyContainer = document.getElementById("privActiveKeyContainerGen");
const privActiveKeyInput = document.getElementById("privActiveKeyGen");
const broadcastButton = document.getElementById("broadcastButtonGen");
const resultMessage3 = document.getElementById("resultMessage3Gen");

let PRIVKEYTOCOPY = null;
let PUBKEYTOBROADCAST = null;

function valCheckButton() {

    if (
        valAccountNameStructure(accountNameInput.value.trim())
        && testedRPCs.length
    ) {
        checkButton.disabled = false;
        checkButton.style.backgroundColor = "green";
    } else {
        privActiveKeyInput.value = "";
        privActiveKeyInput.style.borderColor = "";
        checkButton.disabled = true;
        checkButton.style.backgroundColor = "";
        genButton.disabled = true;
        genButton.style.backgroundColor = "";
        copyButtonGen.disabled = true;
        copyButtonGen.style.backgroundColor = "";
        broadcastButton.disabled = true;
        broadcastButton.style.backgroundColor = "";
        resultMessage1.textContent = "";
        resultMessage2.textContent = "";
        resultMessage3.textContent = "";
        confirmSavedKey.checked = false;
        useHiveKeychain.checked = false;
        resultMsg2Cont.classList.remove("visible");
        confirmCheckboxContainer.classList.remove("visible");
        keychainContainer.classList.remove("visible");
        privActiveKeyContainer.classList.remove("visible");
        PRIVKEYTOCOPY = null;
        PUBKEYTOBROADCAST = null;
    }
}

accountNameInput.addEventListener("input", () => {
    const isValid = valAccountNameStructure(accountNameInput.value.trim());
    accountNameInput.style.borderColor = isValid ? "green" : "red";
});

accountNameInput.addEventListener("input", valCheckButton);

checkButton.addEventListener("click", async () => {

    const userPubHMkey = await fetchPubKey(
        accountNameInput.value.trim(),
        testedRPCs,
    );

    if (userPubHMkey && userPubHMkey instanceof Uint8Array) {
        resultMessage1.textContent = `The account ${accountNameInput.value.trim()} already has a Hive-Mail key`;
    } else {
        resultMessage1.textContent = `The account ${accountNameInput.value.trim()} does not have a Hive-Mail key`;
    }

    PRIVKEYTOCOPY = null;
    PUBKEYTOBROADCAST = null;
    genButton.disabled = false;
    genButton.style.backgroundColor = "green";
});

genButton.addEventListener("click", async () => {

    const { privKey: privHMkey, pubKey: pubHMkey } = await createHMkeyPair();

    resultMessage2.textContent = `New Hive-Mail private key (save it somewhere safe):

${encodeBase91(privHMkey).slice(0, 8)}...`;

    broadcastButton.disabled = true;
    broadcastButton.style.backgroundColor = "";
    resultMessage3.textContent = "";
    confirmSavedKey.checked = false;
    useHiveKeychain.checked = false;
    confirmCheckboxContainer.classList.remove("visible");
    keychainContainer.classList.remove("visible");
    privActiveKeyContainer.classList.remove("visible");

    PRIVKEYTOCOPY = `"${encodeBase91(privHMkey)}"`;
    PUBKEYTOBROADCAST = pubHMkey;
    resultMsg2Cont.classList.add("visible");
    copyButtonGen.disabled = false;
    copyButtonGen.style.backgroundColor = "darkorange";
});

copyButtonGen.addEventListener("click", () => {
    navigator.clipboard.writeText(PRIVKEYTOCOPY)
    .then(() => {
        copyButtonGen.textContent = "Copied!";
        setTimeout(() => copyButtonGen.textContent = "Copy the New Private Key", 5000);
    });
    confirmCheckboxContainer.classList.add("visible");
});

confirmSavedKey.addEventListener("change", () => {
    PRIVKEYTOCOPY = null;
    if (confirmSavedKey.checked) {

        for (let i = 1; !(i > 100); i++) {
            navigator.clipboard.writeText(`Clipboard overwritten! ${i}`);
        }

        keychainContainer.classList.add("visible");
        privActiveKeyContainer.classList.add("visible");
    } else {
        keychainContainer.classList.remove("visible");
        privActiveKeyContainer.classList.remove("visible");
    }
});

function useKeychainCheckboxFn() {
    if (useHiveKeychain.checked) {
        privActiveKeyInput.value = "";
        privActiveKeyInput.style.borderColor = "";
        privActiveKeyContainer.classList.remove("visible");
    } else {
        privActiveKeyInput.value = "";
        privActiveKeyInput.style.borderColor = "";
        privActiveKeyContainer.classList.add("visible");
    }
}

useHiveKeychain.addEventListener("change", useKeychainCheckboxFn);

function confirmationCheckboxFn() {
    if (
        confirmSavedKey.checked
        && valAccountNameStructure(accountNameInput.value.trim())
        && (valHivePrivKey(privActiveKeyInput.value.trim()) || useHiveKeychain.checked)
        && PUBKEYTOBROADCAST
        && PUBKEYTOBROADCAST instanceof Uint8Array
    ) {
        broadcastButton.disabled = false;
        broadcastButton.style.backgroundColor = "red";
    } else {
        broadcastButton.disabled = true;
        broadcastButton.style.backgroundColor = "";
    }
}

accountNameInput.addEventListener("input", confirmationCheckboxFn);
useHiveKeychain.addEventListener("change", confirmationCheckboxFn);
confirmSavedKey.addEventListener("change", confirmationCheckboxFn);
privActiveKeyInput.addEventListener("input", confirmationCheckboxFn);

broadcastButton.addEventListener("click", async () => {

    const metadata = await checkPubKeyOnchain(
        accountNameInput.value.trim(),
        PUBKEYTOBROADCAST,
        testedRPCs,
    );

    if (metadata) {

        if (
            typeof metadata !== "object"
            || Array.isArray(metadata)
            || !valStringCharSet(metadata?.["ჰM0"], customBase91CharSet)
            || !valHMpubKey(decodeBase91(metadata?.["ჰM0"]))
        ) {
            throw new Error(`Invalid metadata received from the "checkPubKeyOnchain" function!`);
        }

        const op = [
            "account_update2",
            {
                account: accountNameInput.value.trim(),
                extensions: [],
                json_metadata: JSON.stringify(metadata, null, 0),
                posting_json_metadata: "",
            },
        ];

        try {

            if (useHiveKeychain.checked) {
                if (window.hive_keychain) {
                    window.hive_keychain.requestBroadcast(accountNameInput.value.trim(), [op], "Active", function(result) {
                        if (result.success) {
                            resultMessage3.textContent = `Transaction successfully broadcast!
Transaction ID: ${result?.result?.id}`;
                            resultMessage3.style.color = "green";
                        } else {
                            resultMessage3.textContent = "Error broadcasting transaction: " + result.message;
                            resultMessage3.style.color = "red";
                        }
                    });
                } else {
                    resultMessage3.textContent = "You need to install Hive Keychain to sign the transaction.";
                    resultMessage3.style.color = "red";
                }
            } else {

                const result2 = await new dhive.Client(shuffleArray(testedRPCs)).broadcast.sendOperations([op], dhive.PrivateKey.fromString(privActiveKeyInput.value.trim()));
                resultMessage3.textContent = `Transaction successfully broadcast!
Transaction ID: ${result2?.id}`;
                resultMessage3.style.color = "green";
            }
        } catch (err) {
            resultMessage3.textContent = "Error broadcasting transaction: " + err.message;
            resultMessage3.style.color = "red";
        }
    } else {
        resultMessage3.textContent = `Failed to save onchain the new Hive-Mail public key!`;
        resultMessage3.style.color = "red";
    }
});

valCheckButton();
