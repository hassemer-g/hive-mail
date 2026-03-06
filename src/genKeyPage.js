import {
    VARS,

} from "./state.js";
import {
    stripOuterQuotes,
} from "./utils.js";
import {
    encBase87,
} from "./base87.js";
import { Client } from "./client.js";
import {
    NODES,
    getRespNodes,
    callHiveNode,
} from "./rpcs.js";
import {
    buildPrivKeyObj,
    valPrivKey,
} from "./key.js";
import {
    Transaction,
} from "./tx.js";
import {
    valAccName,
} from "./val-h.js";
import {
    checkPubKey,
    fetchPubKey,
} from "./hm-pubkeys.js";
import {
    createHMkeyPair,
    valHMpubKey,
} from "./hm-keys.js";

await getRespNodes();

const resultMessage1 = document.getElementById("resultMessage1Gen");

if (!NODES?.length) {
    resultMessage1.style.color = "red";
    resultMessage1.textContent = `Hive RPCs unresponsive! Try again later...`;
}

const accountNameInput = document.getElementById("accountNameGen");
const checkButton = document.getElementById("checkButtonGen");
const genButton = document.getElementById("genButtonGen");
const resultMsg2Container = document.getElementById("resultMsg2GenContainer");
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

function clear() {
    checkButton.disabled = true;
    checkButton.style.backgroundColor = "";
    privActiveKeyInput.value = "";
    privActiveKeyInput.style.borderColor = "";
    genButton.disabled = true;
    genButton.style.backgroundColor = "";
    copyButtonGen.disabled = true;
    copyButtonGen.style.backgroundColor = "";
    broadcastButton.disabled = true;
    broadcastButton.style.backgroundColor = "";
    confirmSavedKey.checked = false;
    useHiveKeychain.checked = false;
    resultMsg2Container.classList.remove("visible");
    confirmCheckboxContainer.classList.remove("visible");
    keychainContainer.classList.remove("visible");
    privActiveKeyContainer.classList.remove("visible");
    VARS[0] = null;
    VARS[1] = null;
    VARS[2] = null;
}

function clearAfterSucc() {
    accountNameInput.value = "";
    accountNameInput.style.borderColor = "";
    clear();
    resultMessage1.textContent = "";
    resultMessage2.textContent = "";
}

function valCheckButton() {
    if (
        valAccName(accountNameInput.value.trim())
        && NODES?.length
        && VARS?.length
    ) {
        checkButton.disabled = false;
        checkButton.style.backgroundColor = "green";

    } else {
        clear();
        resultMessage2.textContent = "";
        resultMessage3.textContent = "";
        if (NODES?.length) { resultMessage1.textContent = ""; }
    }
}

accountNameInput.addEventListener("input", () => {
    const t = accountNameInput.value.trim();
    accountNameInput.style.borderColor = !t ? "" : valAccName(t) ? "green" : "red";
});

accountNameInput.addEventListener("input", valCheckButton);

checkButton.addEventListener("click", async () => {
    const t = accountNameInput.value.trim();

    const [userPubHMkey, metadata] = await fetchPubKey(
        t,
        NODES,
    );

    if (userPubHMkey instanceof Uint8Array && userPubHMkey.length) {
        resultMessage1.textContent = `The account ${t} already has a Hive-Mail key`;
    } else {
        resultMessage1.textContent = `The account ${t} does not have a Hive-Mail key`;
    }

    VARS[0] = null;
    VARS[1] = null;
    VARS[2] = metadata;
    genButton.disabled = false;
    genButton.style.backgroundColor = "green";
});

genButton.addEventListener("click", async () => {

    const [privHMkey, pubHMkey] = await createHMkeyPair();

    resultMessage2.textContent = `New Hive-Mail private key successfully created!
Store it safely before proceeding...`

    broadcastButton.disabled = true;
    broadcastButton.style.backgroundColor = "";
    resultMessage3.textContent = "";
    confirmSavedKey.checked = false;
    useHiveKeychain.checked = false;
    confirmCheckboxContainer.classList.remove("visible");
    keychainContainer.classList.remove("visible");
    privActiveKeyContainer.classList.remove("visible");
    VARS[0] = `${encBase87(privHMkey)}`;
    VARS[1] = pubHMkey;
    resultMsg2Container.classList.add("visible");
    copyButtonGen.disabled = false;
    copyButtonGen.style.backgroundColor = "darkorange";
});

copyButtonGen.addEventListener("click", () => {
    navigator.clipboard.writeText(VARS[0])
    .then(() => {
        copyButtonGen.textContent = "Copied!";
        setTimeout(() => copyButtonGen.textContent = "Copy the New Private Key", 5000);
    });
    confirmCheckboxContainer.classList.add("visible");
});

confirmSavedKey.addEventListener("change", () => {
    VARS[0] = null;
    resultMsg2Container.classList.remove("visible");
    copyButtonGen.disabled = true;
    copyButtonGen.style.backgroundColor = "";
    resultMessage2.textContent = "";
    if (confirmSavedKey.checked) {
        for (let i = 0; i < 100; i++) {
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
        && valAccName(accountNameInput.value.trim())
        && (useHiveKeychain.checked || valPrivKey(stripOuterQuotes(privActiveKeyInput.value.trim())))
        && VARS[1] instanceof Uint8Array
        && VARS[1].length
        && VARS[2]
        && typeof VARS[2] === "object"
        && !Array.isArray(VARS[2])
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
    const privKey = privActiveKeyInput.value.trim();
    privActiveKeyInput.value = "";
    privActiveKeyInput.style.borderColor = "";

    const t = accountNameInput.value.trim();

    broadcastButton.disabled = true;
    broadcastButton.style.backgroundColor = "";
    broadcastButton.textContent = `Broadcasting operation to Hive...`;
    setTimeout(() => {
        broadcastButton.textContent = `Save Onchain the New Public Key`;
        if (useHiveKeychain.checked) {
            broadcastButton.disabled = false;
            broadcastButton.style.backgroundColor = "red";
        }
    }, 5000);

    const ops = await checkPubKey(
        t,
        VARS[1],
        VARS[2],
    );

    if (
        !Array.isArray(ops)
        || !ops.length

    ) {
        resultMessage3.style.color = "red";
        resultMessage3.textContent = `Failed to save onchain the new Hive-Mail public key!`;
    }

    try {

        if (useHiveKeychain.checked) {
            if (window.hive_keychain) {
                window.hive_keychain.requestBroadcast(t, ops, "Active", function(result) {
                    if (result.success) {
                        resultMessage3.style.color = "green";
                        resultMessage3.textContent = `Transaction successfully broadcast!
Transaction ID: ${result?.result?.id}`;
                        clearAfterSucc();

                    } else {
                        resultMessage3.style.color = "red";
                        resultMessage3.textContent = "Error broadcasting transaction: " + result.message;
                    }
                });

            } else {
                resultMessage3.style.color = "red";
                resultMessage3.textContent = "You need to install Hive Keychain to sign the transaction.";
            }

        } else {

            const props = await callHiveNode(
                "get_dynamic_global_properties",
                undefined,
                NODES,
            );

            const tx = new Transaction(props);

            tx.addOperation(ops[0]);

            tx.sign(buildPrivKeyObj(stripOuterQuotes(privKey)));

            const client = new Client(NODES);
            const res = await client.broadcast(
                tx,
            );

            resultMessage3.style.color = "green";
            resultMessage3.textContent = `Transaction successfully broadcast!
Transaction ID: ${res?.tx_id}`;
            clearAfterSucc();
        }

    } catch (err) {
        resultMessage3.style.color = "red";
        resultMessage3.textContent = "Error broadcasting transaction: " + err.message;
    }
});
