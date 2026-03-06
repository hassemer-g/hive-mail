import {
    concatUint8Arr,
    wipeUint8Arr,
    utf8ToBytes,
} from "./utils.js";
import {
    Hs,
    getHs,
} from "./hasher.js";

await getHs();

function myKdf(
    ikm,
    outputOutline = [64],
    H1 = Hs[0],
    H2 = Hs[1],
) {

    const digestSize = H1.digestSize;

    const outLen = outputOutline.length;
    const outputs = new Array(outLen);

    const counter = new Uint8Array(4);

    let C = 0;

    H1.update(ikm);
    H1.update(utf8ToBytes(JSON.stringify(outputOutline).slice(1, -1)));
    const base = H1.save();

    for (let i = 0; i < outLen; i++) {
        const blocks = Math.ceil(outputOutline[i] / digestSize);
        const okm = new Uint8Array(blocks * digestSize);

        for (let j = 0; j < blocks; j++) {

            counter[0] = ++C >>> 24;
            counter[1] = C >>> 16;
            counter[2] = C >>> 8;
            counter[3] = C;

            H1.load(base);
            H1.update(counter);
            const pre1 = H1.digest("binary");
            H1.init();

            H1.update(Uint8Array.of(1));
            H1.update(counter);
            H1.update(pre1);
            const pre2 = H1.digest("binary");
            H1.init();

            H2.update(pre2);
            H2.update(pre1);
            const pre3 = H2.digest("binary");
            H2.init();

            H1.update(Uint8Array.of(252));
            H1.update(pre3);
            H1.update(counter);
            const out = H1.digest("binary");

            okm.set(out, j * digestSize);
        }
        outputs[i] = okm.subarray(0, outputOutline[i]);
    }
    H1.init();

    if (outLen === 1) {
        return outputs[0];
    } else {
        return outputs;
    }
}

function doHash(
    input,
    outCounter,
    outSize,
    H,
) {
    H.update(outCounter);
    H.update(input);
    const base = H.save();

    const counter = new Uint8Array(3);

    let C = 0;

    const digestSize = H.digestSize;
    const blocks = Math.ceil(outSize / digestSize);
    const output = new Uint8Array(blocks * digestSize);

    for (let i = 0; i < blocks; i++) {

        counter[0] = ++C >>> 16;
        counter[1] = C >>> 8;
        counter[2] = C;

        H.load(base);
        H.update(counter);
        const out = H.digest("binary");

        output.set(out, i * digestSize);
    }

    H.init();
    return output.subarray(0, outSize);
}

export function myHash(
    input,
    outputOutline = [64],
    rounds = 10,
    intermSize = 128,
    H = Hs[0],
    toWipeInput = false,
) {

    const counter = new Uint8Array(4);

    let C = 1;

    counter[3] = C;

    const initial = concatUint8Arr(
        input,
        utf8ToBytes(`${input.length} ${JSON.stringify(outputOutline).slice(1, -1)} ${rounds} ${intermSize}`)
    );
    if (toWipeInput) { wipeUint8Arr(input); }

    let mat = doHash(
        initial,
        counter,
        intermSize,
        H,
    );
    if (toWipeInput) { wipeUint8Arr(initial); }

    while (C < rounds) {

        counter[0] = ++C >>> 24;
        counter[1] = C >>> 16;
        counter[2] = C >>> 8;
        counter[3] = C;

        mat = doHash(
            mat,
            counter,
            intermSize,
            H,
        );

    }

    return myKdf(
        mat,
        outputOutline,
        H,
    );
}
