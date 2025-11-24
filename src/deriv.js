import {
    concatBytes,
    utf8ToBytes,
    compareUint8arrays,
    wipeUint8,
} from "./utils.js";
import {
    integerToBytes,
} from "./numbers.js";

function hmac(
    h,
    msg,
    key,
    blockLen,
) {

    if (key.length > blockLen) {
        h.update(key);
        key = h.digest("binary");
        h.init();
    }

    const keyPadded = new Uint8Array(blockLen);
    keyPadded.set(key.length ? key : new Uint8Array(0));
    const ipad = new Uint8Array(blockLen);
    const opad = new Uint8Array(blockLen);
    for (let i = 0; i < blockLen; i++) {
        const b = keyPadded[i];
        ipad[i] = b ^ 0x36;
        opad[i] = b ^ 0x5c;
    }

    h.update(ipad);
    h.update(msg);
    const inner = h.digest("binary");
    h.init();

    h.update(opad);
    h.update(inner);
    const out = h.digest("binary");
    h.init();

    return out;
}
export function doHKDF(
    h,
    ikm,
    info = new Uint8Array(0),
    salt = undefined,
    length = undefined,
) {

    const blockLen = h.blockSize;
    const outputLen = h.digestSize;

    if (length === undefined)
        length = outputLen;

    if (salt === undefined)
        salt = new Uint8Array(blockLen);

    const prk = hmac(
        h,
        ikm,
        salt,
        blockLen,
    );
    wipeUint8(ikm, salt);

    const blocks = Math.ceil(length / outputLen);
    const okm = new Uint8Array(blocks * outputLen);

    let prev = new Uint8Array(0);
    let havePrev = false;
    const counter = new Uint8Array(1);

    let prkKey = prk;
    if (prkKey.length > blockLen) {
        h.update(prkKey);
        prkKey = h.digest("binary");
        h.init();
    }

    const keyPadded = new Uint8Array(blockLen);
    keyPadded.set(prkKey);
    const ipad = new Uint8Array(blockLen);
    const opad = new Uint8Array(blockLen);
    for (let i = 0; i < blockLen; i++) {
        const b = keyPadded[i];
        ipad[i] = b ^ 0x36;
        opad[i] = b ^ 0x5c;
    }

    h.update(ipad);
    const innerBaseState = h.save();
    h.init();

    h.update(opad);
    const outerBaseState = h.save();
    h.init();

    for (let i = 0; i < blocks; i++) {
        counter[0] = i + 1;

        h.load(innerBaseState);
        if (havePrev) h.update(prev);
        if (info.length) h.update(info);
        h.update(counter);
        const inner = h.digest("binary");
        h.init();

        h.load(outerBaseState);
        h.update(inner);
        prev = h.digest("binary");
        if (!havePrev) havePrev = true;
        h.init();

        okm.set(prev, i * outputLen);
    }

    return okm.slice(0, length);
}

export function doHashing(
    input,
    Hs,
    outputOutline = [64],
    rounds = 5,
) {

    let hashMat, salt, passwPt1, passwPt2, passwPt3;
    for (let i = 1; !(i > rounds); i++) {

        const itInput =
            i === 1 ? concatBytes(integerToBytes(i), utf8ToBytes(`${input.length} ${rounds} ${JSON.stringify(outputOutline, null, 0)}`), input)
            : concatBytes(integerToBytes(i), hashMat);
        wipeUint8(input);

        const hashArray = [];
        for (const [j, [, fn]] of Object.entries(Hs).entries()) {
            fn.update(concatBytes(integerToBytes(j), itInput));
            hashArray.push(fn.digest("binary"));
            fn.init();
        }

        const order1 = compareUint8arrays(hashArray[1], hashArray[2]);
        const order2 = compareUint8arrays(hashArray[0], hashArray[3]);
        const order3 = compareUint8arrays(hashArray[4], hashArray[5]);

        if (order1 < 0) {
            if (order2 < 0) {
                if (order3 < 0) {
                    hashMat = concatBytes(...(hashArray.map(u => u.reverse()).sort(compareUint8arrays).reverse())).reverse()
                } else {
                    hashMat = concatBytes(...(hashArray.map(u => u.reverse()).sort(compareUint8arrays))).reverse()
                }
            } else {
                if (order3 < 0) {
                    hashMat = concatBytes(...(hashArray.map(u => u.reverse()).sort(compareUint8arrays).reverse()))
                } else {
                    hashMat = concatBytes(...(hashArray.map(u => u.reverse()).sort(compareUint8arrays)))
                }
            }
        } else {
            if (order2 < 0) {
                if (order3 < 0) {
                    hashMat = concatBytes(...(hashArray.sort(compareUint8arrays).reverse())).reverse()
                } else {
                    hashMat = concatBytes(...(hashArray.sort(compareUint8arrays))).reverse()
                }
            } else {
                if (order3 < 0) {
                    hashMat = concatBytes(...(hashArray.sort(compareUint8arrays).reverse()))
                } else {
                    hashMat = concatBytes(...(hashArray.sort(compareUint8arrays)))
                }
            }
        }

        if (i === rounds - 3) { salt = hashMat.slice(100, 172); }
        else if (i === rounds - 2) { passwPt1 = hashMat; }
        else if (i === rounds - 1) { passwPt2 = hashMat; }
        else if (i === rounds) { passwPt3 = hashMat; }
    }

    const passw = concatBytes(passwPt3, passwPt2, passwPt1);

    const outputs = [];
    let i = 1;
    for (const elementLength of outputOutline) {

        const iBytes = integerToBytes(i);

        outputs.push(doHKDF(
            Hs.sha3,
            concatBytes(iBytes, integerToBytes(elementLength), passw),
            iBytes,
            salt,
            elementLength,
        ));

        i++;
    }

    if (outputs.length === 1) {
        return outputs[0];
    } else {
        return outputs;
    }
}
