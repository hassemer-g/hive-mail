import dhive from "./dhive/dhive.mjs";
import {
    shuffleArray,
} from "./utils.js";
import {
    decodeBase64,
} from "./base64.js";
import {
    encodeBase91,
    decodeBase91,
} from "./base91.js";
import { valStringCharSet } from "./val.js";
import {
    urlSafeBase64CharSet,
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
    const t = accountNameInput.value.trim();
    accountNameInput.style.borderColor = !t ? "" : valAccountNameStructure(t) ? "green" : "red";
});

accountNameInput.addEventListener("input", valCheckButton);

checkButton.addEventListener("click", async () => {
    const t = accountNameInput.value.trim();

    const userPubHMkey = await fetchPubKey(
        t,
        testedRPCs,
    );

    if (userPubHMkey && userPubHMkey instanceof Uint8Array) {
        resultMessage1.textContent = `The account ${t} already has a Hive-Mail key`;
    } else {
        resultMessage1.textContent = `The account ${t} does not have a Hive-Mail key`;
    }

    PRIVKEYTOCOPY = null;
    PUBKEYTOBROADCAST = null;
    genButton.disabled = false;
    genButton.style.backgroundColor = "green";
});

genButton.addEventListener("click", async () => {
    const { privKey: privHMkey, pubKey: pubHMkey } = await createHMkeyPair();
    resultMessage2.textContent = `New Hive-Mail private key (save it somewhere safe):

${encodeBase91(privHMkey).slice(0, 32)}...`;

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
    const privKey = privActiveKeyInput.value.trim();

    privActiveKeyInput.value = "";
    privActiveKeyInput.style.borderColor = "";

    const t = accountNameInput.value.trim()
    .then(() => {
        broadcastButton.disabled = true;
        broadcastButton.textContent = `Broadcasting operation to Hive...`;
        setTimeout(() => {
            broadcastButton.textContent = `Save Onchain the New Public Key`;
            broadcastButton.disabled = false;
        }, 5000);
    });

    const metadata = await checkPubKeyOnchain(
        t,
        PUBKEYTOBROADCAST,
        testedRPCs,
    );

    if (metadata) {

        if (
            typeof metadata !== "object"
            || Array.isArray(metadata)
            || !valStringCharSet(metadata?.["ჰM"]?.[1], urlSafeBase64CharSet)
            || !valHMpubKey(decodeBase64(metadata?.["ჰM"]?.[1]))
        ) { throw new Error(`Invalid metadata received from the "checkPubKeyOnchain" function!`); }

        const op = [
            "account_update2",
            {
                account: t,
                extensions: [],
                json_metadata: JSON.stringify(metadata),
                posting_json_metadata: "",
            },
        ];

        try {

            if (useHiveKeychain.checked) {
                if (window.hive_keychain) {
                    window.hive_keychain.requestBroadcast(t, [op], "Active", function(result) {
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

                const result2 = await new dhive.Client(shuffleArray(testedRPCs)).broadcast.sendOperations([op], dhive.PrivateKey.fromString(privKey));
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
