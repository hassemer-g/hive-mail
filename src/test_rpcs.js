import dhive from "./dhive/dhive.mjs";

import { shuffleArray } from "./utils.js";

export async function testRPCsWithDhive(
    RPCs,
    shuffleNeeded = false,
    timeoutMs = 2000,
) {

    if (!Array.isArray(RPCs) || RPCs.length < 1 || RPCs.some(v => typeof v !== "string")) {
        throw new Error(`Invalid RPCs input! Expected an array of strings.`);
    }

    const timeoutPromise = ms => new Promise(resolve => setTimeout(resolve, ms, "timeout"));

    const testRPC = async (url) => {
        try {
            const client = new dhive.Client(url, { timeout: timeoutMs });
            const result = await Promise.race([
                client.database.getVersion(),
                timeoutPromise(timeoutMs),
            ]);
            return result !== "timeout" ? url : null;
        } catch {
            return null;
        }
    };

    const results = await Promise.all(RPCs.map(testRPC));

    const responsive = results.filter(Boolean);
    return shuffleNeeded ? shuffleArray(responsive) : responsive;
}
