import dhive from "./dhive/dhive.mjs";

import {
    shuffleArray,
} from "./utils.js";
import { RPCsArray } from "./rpcs.js";
import { testRPCsWithDhive } from "./test_rpcs.js";
import {
    valAccountNameStructure,
    valHivePrivKey,
} from "./val-h.js";
import {
    checkForRemoval,
    removeHMitems,
} from "./hm-pubkeys.js";

const testedRPCs = await testRPCsWithDhive(RPCsArray);
console.log("testedRPCs: ", testedRPCs);

const resultMessage1 = document.getElementById("resultMessage1Rem");

if (!testedRPCs || !testedRPCs.length) {
    resultMessage1.textContent = `All Hive RPCs are unresponsive! Try again later...`;
    resultMessage1.style.color = "red";
}

const accountNameInput = document.getElementById("accountNameRem");
const checkButton = document.getElementById("checkButtonRem");
const keychainContainer = document.getElementById("keychainContainerRem");
const useHiveKeychain = document.getElementById("useHiveKeychainRem");
const privActiveKeyContainer = document.getElementById("privActiveKeyContainerRem");
const privActiveKeyInput = document.getElementById("privActiveKeyRem");
const removeButton = document.getElementById("removeButton");
const resultMessage2 = document.getElementById("resultMessage2Rem");

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
        removeButton.disabled = true;
        removeButton.style.backgroundColor = "";
        resultMessage1.textContent = "";
        resultMessage2.textContent = "";
        useHiveKeychain.checked = false;
        keychainContainer.classList.remove("visible");
        privActiveKeyContainer.classList.remove("visible");
    }
}

accountNameInput.addEventListener("input", () => {
    const isValid = valAccountNameStructure(accountNameInput.value.trim());
    accountNameInput.style.borderColor = isValid ? "green" : "red";
});

accountNameInput.addEventListener("input", valCheckButton);

checkButton.addEventListener("click", async () => {

    const canBeCleaned = await checkForRemoval(
        accountNameInput.value.trim(),
        testedRPCs,
    );

    if (canBeCleaned) {
        keychainContainer.classList.add("visible");
        privActiveKeyContainer.classList.add("visible");
        resultMessage1.textContent = `The account ${accountNameInput.value.trim()} has Hive-Mail elements in its metadata`;
    } else {
        keychainContainer.classList.remove("visible");
        privActiveKeyContainer.classList.remove("visible");
        removeButton.disabled = true;
        removeButton.style.backgroundColor = "";
        resultMessage1.textContent = `There is nothing to remove from the metadata of account ${accountNameInput.value.trim()}`;
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
        valAccountNameStructure(accountNameInput.value.trim())
        && (valHivePrivKey(privActiveKeyInput.value.trim()) || useHiveKeychain.checked)
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

    const metadata = await removeHMitems(
        accountNameInput.value.trim(),
        testedRPCs,
    );

    if (metadata) {

        if (
            typeof metadata !== "object"
            || Array.isArray(metadata)
        ) {
            throw new Error(`Invalid metadata received from the "removeHMitems" function!`);
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
                            resultMessage2.textContent = `Success in removing all Hive-Mail elements from the metadata of account ${accountNameInput.value.trim()}
Transaction ID: ${result?.result?.id}`;
                            resultMessage2.style.color = "green";
                        } else {
                            resultMessage2.textContent = `Failed to remove the Hive-Mail elements from the metadata of account ${accountNameInput.value.trim()}
Error message: ${result?.message}`;
                            resultMessage2.style.color = "red";
                        }
                    });
                } else {
                    resultMessage2.textContent = "You need to install Hive Keychain to sign the transaction.";
                    resultMessage2.style.color = "red";
                }
            } else {

                const result2 = await new dhive.Client(shuffleArray(testedRPCs)).broadcast.sendOperations([op], dhive.PrivateKey.fromString(privActiveKeyInput.value.trim()));
                resultMessage2.textContent = `Success in removing all Hive-Mail elements from the metadata of account ${accountNameInput.value.trim()}
Transaction ID: ${result2?.id}`;
                resultMessage2.style.color = "green";
            }
        } catch (err) {
            resultMessage2.textContent = `Failed to remove the Hive-Mail elements from the metadata of account ${accountNameInput.value.trim()}
Error message: ${err.message}`;
            resultMessage2.style.color = "red";
        }

    } else {
        resultMessage2.textContent = `Failed to save onchain the cleaned metadata!`;
        resultMessage2.style.color = "red";
    }
});

valCheckButton();
