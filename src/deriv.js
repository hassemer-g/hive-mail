import {
    concatBytes,
    utf8ToBytes,
    compareUint8arrays,
    wipeUint8,
} from "./utils.js";

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

function doHKDF(
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
    toWipeInput = false,
) {

    const iUint8 = new Uint8Array(4);
    const iView = new DataView(iUint8.buffer);

    let i = 1 >>> 0;
    iView.setUint32(0, i, true);
    const initInput = concatBytes(iUint8, utf8ToBytes(`${input.length} ${rounds} ${JSON.stringify(outputOutline)}`), input);
    if (toWipeInput) { wipeUint8(input); }

    const jUint8 = new Uint8Array(4);
    const jView = new DataView(jUint8.buffer);

    const initHashArray = [];
    let j = 0 >>> 0;
    for (const [, fn] of Object.entries(Hs)) {
        j = (j + 1) >>> 0;
        jView.setUint32(0, j, true);
        fn.update(jUint8);
        fn.update(initInput);
        initHashArray.push(fn.digest("binary"));
        fn.init();
    }
    wipeUint8(initInput);
    j = 0 >>> 0;

    let hashMat = concatBytes(...(initHashArray.map(u => u.reverse()).sort(compareUint8arrays).reverse())).reverse();

    let salt, passwPt1, passwPt2, passwPt3;

    while (i < rounds) {

        i = (i + 1) >>> 0;
        iView.setUint32(0, i, true);
        const itInput = concatBytes(iUint8, hashMat);

        const hashArray = [];
        for (const [, fn] of Object.entries(Hs)) {
            j = (j + 1) >>> 0;
            jView.setUint32(0, j, true);
            fn.update(jUint8);
            fn.update(itInput);
            hashArray.push(fn.digest("binary"));
            fn.init();
        }
        j = 0 >>> 0;

        const order1 = compareUint8arrays(hashArray[1], hashArray[2]);
        const order2 = compareUint8arrays(hashArray[0], hashArray[3]);
        const order3 = compareUint8arrays(hashArray[4], hashArray[5]);

        if (order1 < 0) {
            if (order2 < 0) {
                if (order3 < 0) {
                    hashMat = concatBytes(...(hashArray.map(u => u.reverse()).sort(compareUint8arrays).reverse())).reverse();
                } else {
                    hashMat = concatBytes(...(hashArray.map(u => u.reverse()).sort(compareUint8arrays))).reverse();
                }
            } else {
                if (order3 < 0) {
                    hashMat = concatBytes(...(hashArray.map(u => u.reverse()).sort(compareUint8arrays).reverse()));
                } else {
                    hashMat = concatBytes(...(hashArray.map(u => u.reverse()).sort(compareUint8arrays)));
                }
            }
        } else {
            if (order2 < 0) {
                if (order3 < 0) {
                    hashMat = concatBytes(...(hashArray.sort(compareUint8arrays).reverse())).reverse();
                } else {
                    hashMat = concatBytes(...(hashArray.sort(compareUint8arrays))).reverse();
                }
            } else {
                if (order3 < 0) {
                    hashMat = concatBytes(...(hashArray.sort(compareUint8arrays).reverse()));
                } else {
                    hashMat = concatBytes(...(hashArray.sort(compareUint8arrays)));
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
    i = 0 >>> 0;
    for (const elementLength of outputOutline) {

        i = (i + 1) >>> 0;
        iView.setUint32(0, i, true);
        outputs.push(doHKDF(
            Hs.sha3,
            passw,
            iUint8,
            salt,
            elementLength,
        ));
    }

    if (outputs.length === 1) {
        return outputs[0];
    } else {
        return outputs;
    }
}
