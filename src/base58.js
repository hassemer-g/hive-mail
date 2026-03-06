import {
    createBase,
} from "./baseX.js";
import {
    base58CharSet,
} from "./charsets.js";

export const [encBase58, decBase58] = createBase(base58CharSet);
