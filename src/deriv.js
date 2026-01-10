import {
    concatUint8Arr,
    wipeUint8Arr,
    utf8ToBytes,
} from "./utils.js";

function getDerivs(
    ikm,
    key,
    H,
) {
    H.update(new Uint8Array([1]));
    H.update(ikm);
    H.update(key);
    const out1 = H.digest("binary");
    H.init();
    H.update(new Uint8Array([252]));
    H.update(out1);
    H.update(ikm);
    const out2 = H.digest("binary");
    H.init();
    return [out1, out2];
}

function customKdf(
    H,
    ikm,
    outputOutline,
) {
    const digestSize = H.digestSize;
    const outLen = outputOutline.length;
    const outputs = new Array(outLen);

    const counter = new Uint8Array(4);
    const counterView = new DataView(counter.buffer);
    let C = 0;

    counterView.setUint32(0, C, true);
    H.update(counter);
    H.update(ikm);
    let hashed = H.digest("binary");
    H.init();

    const [deriv1, deriv2] = getDerivs(
        ikm,
        hashed,
        H,
    );

    H.update(deriv1);
    H.update(deriv2);
    const derivs = H.save();
    H.init();

    for (let i = 0; i < outLen; i++) {
        const blocks = Math.ceil(outputOutline[i] / digestSize);
        const okm = new Uint8Array(blocks * digestSize);

        for (let j = 0; j < blocks; j++) {
            counterView.setUint32(0, ++C, true);

            H.load(derivs);
            H.update(counter);
            H.update(hashed);
            hashed = H.digest("binary");
            H.init();

            okm.set(hashed, j * digestSize);
        }
        outputs[i] = okm.slice(0, outputOutline[i]);
    }

    if (outLen === 1) {
        return outputs[0];
    } else {
        return outputs;
    }
}

function spHashRound(
    input,
    Hs,
    outputLength = 128,
) {
    const outLen = Hs.length;
    const outArr = new Array(outLen);
    for (let i = 0; i < outLen; i++) {
        outArr[i] = customKdf(
            Hs[i],
            input,
            [outputLength],
        );
    }
    return outArr;
}

export function doHashing(
    input,
    Hs,
    outputOutline = [64],
    rounds = 3,
    toWipeInput = false,
) {
    const counter = new Uint8Array(4);
    const counterView = new DataView(counter.buffer);
    let C = 1;

    counterView.setUint32(0, C, true);
    let hashMat = concatUint8Arr(...spHashRound(
        concatUint8Arr(counter, utf8ToBytes(`${input.length} ${rounds} ${JSON.stringify(outputOutline)}`), input),
        Hs,
    ));
    if (toWipeInput) { wipeUint8Arr(input); }

    while (C < rounds) {
        counterView.setUint32(0, ++C, true);
        hashMat = concatUint8Arr(...spHashRound(
            concatUint8Arr(counter, hashMat),
            Hs,
        ));
    }

    return customKdf(
        Hs[0],
        hashMat,
        outputOutline,
    );
}
