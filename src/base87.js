import {
    createBase,
} from "./baseX.js";
import {
    base87CharSet,
} from "./charsets.js";

export const [encBase87, decBase87] = createBase(base87CharSet);
