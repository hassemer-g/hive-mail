import {
    VARS,

} from "./state.js";
import {
    stripOuterQuotes,
} from "./utils.js";
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
    checkForRemoval,
    removeHMitems,
} from "./hm-pubkeys.js";

await getRespNodes();

const resultMessage1 = document.getElementById("resultMessage1Rem");

if (!NODES?.length) {
    resultMessage1.style.color = "red";
    resultMessage1.textContent = `Hive RPCs unresponsive! Try again later...`;
}

const accountNameInput = document.getElementById("accountNameRem");
const checkButton = document.getElementById("checkButtonRem");
const keychainContainer = document.getElementById("keychainContainerRem");
const useHiveKeychain = document.getElementById("useHiveKeychainRem");
const privActiveKeyContainer = document.getElementById("privActiveKeyContainerRem");
const privActiveKeyInput = document.getElementById("privActiveKeyRem");
const removeButton = document.getElementById("removeButton");
const resultMessage2 = document.getElementById("resultMessage2Rem");

function clearAfterSucc() {
    accountNameInput.value = "";
    accountNameInput.style.borderColor = "";
    checkButton.disabled = true;
    checkButton.style.backgroundColor = "";
    removeButton.disabled = true;
    removeButton.style.backgroundColor = "";
    resultMessage1.textContent = "";
    useHiveKeychain.checked = false;
    keychainContainer.classList.remove("visible");
    privActiveKeyContainer.classList.remove("visible");
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
        privActiveKeyInput.value = "";
        privActiveKeyInput.style.borderColor = "";
        checkButton.disabled = true;
        checkButton.style.backgroundColor = "";
        removeButton.disabled = true;
        removeButton.style.backgroundColor = "";
        resultMessage2.textContent = "";
        useHiveKeychain.checked = false;
        keychainContainer.classList.remove("visible");
        privActiveKeyContainer.classList.remove("visible");
        VARS[0] = null;
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

    const [canBeCleaned, metadata] = await checkForRemoval(
        t,
        NODES,
    );

    if (canBeCleaned) {
        VARS[0] = metadata;
        keychainContainer.classList.add("visible");
        privActiveKeyContainer.classList.add("visible");
        resultMessage1.textContent = `The account ${t} has Hive-Mail elements in its metadata`;
    } else {
        VARS[0] = null;
        keychainContainer.classList.remove("visible");
        privActiveKeyContainer.classList.remove("visible");
        removeButton.disabled = true;
        removeButton.style.backgroundColor = "";
        resultMessage1.textContent = `There is nothing to remove from the metadata of account ${t}`;
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

function valRemoveButton() {
    if (
        valAccName(accountNameInput.value.trim())
        && (useHiveKeychain.checked || valPrivKey(stripOuterQuotes(privActiveKeyInput.value.trim())))
        && VARS[0]
        && typeof VARS[0] === "object"
        && !Array.isArray(VARS[0])
    ) {
        removeButton.disabled = false;
        removeButton.style.backgroundColor = "red";
    } else {
        removeButton.disabled = true;
        removeButton.style.backgroundColor = "";
    }
}

accountNameInput.addEventListener("input", valRemoveButton);
useHiveKeychain.addEventListener("change", valRemoveButton);
privActiveKeyInput.addEventListener("input", valRemoveButton);

removeButton.addEventListener("click", async () => {
    const privKey = privActiveKeyInput.value.trim();
    privActiveKeyInput.value = "";
    privActiveKeyInput.style.borderColor = "";

    const t = accountNameInput.value.trim();

    removeButton.disabled = true;
    removeButton.style.backgroundColor = "";
    removeButton.textContent = `Broadcasting operation to Hive...`;
    setTimeout(() => {
        removeButton.textContent = `Remove Hive-Mail Key`;
        if (useHiveKeychain.checked) {
            removeButton.disabled = false;
            removeButton.style.backgroundColor = "red";
        }
    }, 5000);

    const ops = await removeHMitems(
        t,
        VARS[0],
    );

    if (
        !Array.isArray(ops)
        || !ops.length
    ) {

        resultMessage2.style.color = "red";
        resultMessage2.textContent = `Failed to save onchain the cleaned metadata`;
    }

    try {

        if (useHiveKeychain.checked) {
            if (window.hive_keychain) {
                window.hive_keychain.requestBroadcast(t, ops, "Active", function(result) {
                    if (result.success) {
                        resultMessage2.style.color = "green";
                        resultMessage2.textContent = `Success in removing all Hive-Mail elements from the metadata of account ${t}
Transaction ID: ${result?.result?.id}`;
                        clearAfterSucc();

                    } else {
                        resultMessage2.style.color = "red";
                        resultMessage2.textContent = `Failed to remove the Hive-Mail elements from the metadata of account ${t}
Error message: ${result?.message}`;
                    }
                });

            } else {
                resultMessage2.style.color = "red";
                resultMessage2.textContent = "You need to install Hive Keychain to sign the transaction.";
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

            resultMessage2.style.color = "green";
            resultMessage2.textContent = `Success in removing all Hive-Mail elements from the metadata of account ${t}
Transaction ID: ${res?.tx_id}`;
            clearAfterSucc();
        }

    } catch (err) {
        resultMessage2.style.color = "red";
        resultMessage2.textContent = `Failed to remove the Hive-Mail elements from the metadata of account ${t}
Error message: ${err.message}`;
    }
});
