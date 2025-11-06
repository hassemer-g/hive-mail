import {
    concatBytes,
    utf8ToBytes,
    compareUint8arrays,
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
    outputLength = 64,
    rounds = 1,
) {

    Hs.whirlpool.update(concatBytes(input, utf8ToBytes(`${input.length} ${rounds} ${outputLength}`)));
    const markInit1 = Hs.whirlpool.digest("binary");
    Hs.whirlpool.init();
    Hs.sha3.update(concatBytes(utf8ToBytes(`${input.length} ${rounds} ${outputLength}`), markInit1, input));
    const markInit2 = Hs.sha3.digest("binary");
    Hs.sha3.init();
    let mark = concatBytes(markInit2, markInit1);

    let output = new Uint8Array(0);
    for (let i = 1; !(i > rounds); i++) {

        const prevMark = mark;

        Hs.sha3.update(concatBytes(utf8ToBytes(`${i} ${input.length} ${rounds} ${outputLength}`), prevMark, output));
        mark = concatBytes(prevMark.subarray(64, 96), Hs.sha3.digest("binary"), prevMark.subarray(32, 64));
        Hs.sha3.init();

        const markedInput = concatBytes(mark, input);

        const hashArray = [];
        for (const [name, fn] of Object.entries(Hs)) {
            fn.update(markedInput);
            hashArray.push(fn.digest("binary"));
            fn.init();
        }

        const itConcat = concatBytes(...(hashArray.sort(compareUint8arrays)));

        output = doHKDF(
            compareUint8arrays(mark, prevMark) < 0 ? Hs.sha2 : Hs.blake2,
            concatBytes(itConcat, input),
            integerToBytes(i),
            mark,
            i === rounds ? outputLength : 16320,
        );
    }

    return output;
}

export function derivMult(
    passw,
    salt,
    outputOutline,
    Hs,
) {

    const numberOfElements = outputOutline.length;
    let outlineSum = 0;
    for (let i = 0; i < numberOfElements; i++) outlineSum += outputOutline[i];

    const elements = [];
    let i = 1;
    for (const elLength of outputOutline) {

        const prevSalt = salt;

        Hs.sha3.update(concatBytes(utf8ToBytes(`${i} ${passw.length} ${numberOfElements} ${outlineSum} ${elLength}`), prevSalt));
        salt = concatBytes(prevSalt.subarray(64, 96), Hs.sha3.digest("binary"), prevSalt.subarray(32, 64));
        Hs.sha3.init();

        elements.push(doHKDF(
            compareUint8arrays(salt, prevSalt) < 0 ? Hs.sha2 : Hs.blake2,
            concatBytes(salt, passw),
            integerToBytes(i),
            salt,
            elLength,
        ));

        i++;
    }

    return elements;
}
