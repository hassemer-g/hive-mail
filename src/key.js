import {
    sha256,
    sha512,
} from "./noble-hashes/sha2.js";
import { ripemd160 } from "./noble-hashes/legacy.js";
import { secp256k1 } from "./noble-curves/secp256k1.js";

import {
    utf8ToBytes,
    bytesToHex,
    hexToBytes,
} from "./utils.js";
import {
    decBase58,
    encBase58,
} from "./base58.js";

const NETWORK_ID = 0x80;
const prefix = "STM";

export function valPrivKey(input) {
    if (!Array.isArray(input)) { input = [input]; }
    const len = input.length;
    for (let i = 0; i < len; i++) {
        if (
            typeof input[i] !== "string"
            || input[i].length !== 51
            || !/^5[1-9A-HJ-NP-Za-km-z]{50}$/.test(input[i])
        ) { return false; }
    }
    return true;
}

export function valPubKey(input) {
    if (!Array.isArray(input)) { input = [input]; }
    const len = input.length;
    for (let i = 0; i < len; i++) {
        if (
            typeof input[i] !== "string"
            || input[i].length !== 53
            || !/^STM[1-9A-HJ-NP-Za-km-z]{50}$/.test(input[i])
        ) { return false; }
    }
    return true;
}

function doubleSha256(bytes) {
    return sha256(sha256(bytes));
}

function decPrivKey(wif) {

    const decoded = decBase58(wif);

    if (decoded[0] !== NETWORK_ID)
        throw new Error("Hive private key network id mismatch");

    const payload = decoded.slice(0, -4);
    const checksum = decoded.slice(-4);
    const verify = doubleSha256(payload).slice(0, 4);

    for (let i = 0; i < 4; i++) {
        if (checksum[i] !== verify[i])
            throw new Error("Hive private key checksum mismatch");
    }

    return payload.slice(1);
}

function encPrivKey(keyBytes) {
    const payload = new Uint8Array([NETWORK_ID, ...keyBytes]);
    const checksum = doubleSha256(payload).slice(0, 4);
    return encBase58(new Uint8Array([...payload, ...checksum]));
}

function encPubKey(pubBytes) {
    const checksum = ripemd160(pubBytes).slice(0, 4);
    const pub = prefix + encBase58(new Uint8Array([...pubBytes, ...checksum]));

    if (!valPubKey(pub)) throw new Error("Invalid derived Hive public key");
    return pub;
}

function decPubKey(pub) {

    const body = decBase58(pub.slice(3));
    const key = body.slice(0, body.length - 4);
    if (key.length !== 33) {
        throw new Error("Invalid public key length");
    }
    return key;
}

function signRecoverable(message32, keyBytes) {
    const sig = secp256k1.sign(message32, keyBytes, {
        extraEntropy: true,
        format: "recovered",
        prehash: false,
    });

    const recovery = sig[0];
    const compact = sig.slice(1);

    const out = new Uint8Array(65);
    out[0] = (recovery + 31) & 0xff;
    out.set(compact, 1);

    return bytesToHex(out);
}

export function buildPubKeyObj(input) {
    let key, pubString;
    if (
        input instanceof Uint8Array
        && input.length === 33
    ) {
        key = input;
        pubString = encPubKey(key);
    } else if (valPubKey(input)) {
        key = decPubKey(input);
        pubString = input;
    } else if (
        input?.key instanceof Uint8Array
        && input.key.length === 33
    ) {
        key = input.key;
        pubString = typeof input.toString === "function"
            ? input.toString()
            : encPubKey(key);
    } else {
        throw new Error(`Invalid input for buildPubKeyObj`);
    }

    return {
        key,
        prefix,

        verify(message32, signature) {
            signature = typeof signature === "string" ? sigFrom(signature) : signature;

            return secp256k1.verify(
                signature.data,
                message32,
                key,
                { prehash: false, format: "compact" },
            );
        },

        toString() {
            return pubString;
        },

        toJSON() {
            return pubString;
        },

        inspect() {
            return `PublicKey: ${pubString}`;
        },
    };
}

function buildSignObj(hex) {
    const temp = hexToBytes(hex);

    let recovery = temp[0] - 31;
    let compressed = true;

    if (recovery < 0) {
        compressed = false;
        recovery += 4;
    }

    const data = temp.slice(1);

    return {
        data,
        recovery,
        compressed,

        toBuffer() {
            const buffer = new Uint8Array(65);
            buffer[0] = (compressed ? recovery + 31 : recovery + 27) & 0xff;
            buffer.set(data, 1);
            return buffer;
        },

        customToString() {
            return bytesToHex(this.toBuffer());
        }
    };
}

function sigFrom(value) {
    if (typeof value === "string") {
        return buildSignObj(value);
    }
    if (value?.data instanceof Uint8Array) {
        return value;
    }
    throw new Error("Invalid signature");
}

export function buildPrivKeyObj(
    input,
    type = 1,
) {
    let keyBytes;
    if (
        type === 1
        && valPrivKey(input)
    ) {
        keyBytes = decPrivKey(input);
    } else if (
        type === 2
        && input instanceof Uint8Array
        && input.length === 32
    ) {
        keyBytes = input;
    } else if (
        type === 3
        && typeof input === "string"
        && input.length > 20
    ) {
        keyBytes = sha256(utf8ToBytes(input));
    } else {
        throw new Error("Invalid private key material provided");
    }

    secp256k1.getPublicKey(keyBytes, true);

    return {
        key: keyBytes,

        sign(message32) {
            return buildSignObj(signRecoverable(message32, keyBytes));
        },

        createPublic() {
            return buildPubKeyObj(secp256k1.getPublicKey(keyBytes, true));
        },

        toString() {
            return encPrivKey(keyBytes);
        },

        inspect() {
            const wif = encPrivKey(keyBytes);
            return `PrivateKey: ${wif.slice(0, 6)}...${wif.slice(-6)}`;
        },

        getSharedSecret(publicKey) {
            let pubBytes;

            if (valPubKey(publicKey)) {
                pubBytes = decPubKey(publicKey);
            } else if (publicKey?.key instanceof Uint8Array) {
                pubBytes = publicKey.key;
            } else {
                throw new Error("Invalid public key");
            }

            const secret = secp256k1.getSharedSecret(keyBytes, pubBytes);
            return sha512(secret.slice(1));
        },
    };
}
