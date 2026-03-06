import {
    createSHA3,
    createBLAKE2b,
} from "./hash-wasm/hash-wasm.js";

export let Hs = null;
export async function getHs() {
    if (!Hs) {

        console.log(`
Building "Hs"...
`);

        Hs = [
            await createSHA3(),
            await createBLAKE2b(),
        ];
    }
}
