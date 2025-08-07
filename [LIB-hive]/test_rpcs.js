import { shuffleArray } from "../[LIB]/shuffle_array.js";


// ==================================================================== //


// Test Hive RPCs
export async function testRPCs(
    RPCs, // an array of strings
    timeoutMs = 5000,
    shuffleNeeded = false,
) {

    try {

        /*
        // Debugging
        console.log("\"RPCs\":", RPCs);
        console.log("\"RPCs\" length:", RPCs.length);
        console.log(Array.isArray(RPCs));
        console.log(RPCs.every(item => typeof item === "string"));
        */

        // Ensure adequate input
        if (!Array.isArray(RPCs) || RPCs.length === 0 || !(RPCs.every(item => typeof item === "string"))) {
            throw new Error(`Invalid input! Expected an array of strings.`);
        }

        const fetchWithTimeout = async (url, timeout) => {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), timeout);

            const payload = {
                jsonrpc: "2.0",
                method: "condenser_api.get_dynamic_global_properties",
                params: [],
                id: 1,
            };

            try {
                const response = await fetch(url, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(payload),
                    signal: controller.signal,
                });

                if (!response.ok) return false;

                const json = await response.json();
                return !!json.result;

            } catch {
                return false;

            } finally {
                clearTimeout(timer);
            }
        };

        const results = await Promise.all(
            RPCs.map(async (url) => {
                const ok = await fetchWithTimeout(url, timeoutMs);
                return ok ? url : null;
            })
        );

        const responsive = results.filter(Boolean);

        console.log("Responsive Hive RPCs:", responsive);

        if (shuffleNeeded) {
            return shuffleArray(responsive); // an array of strings

        } else {
            return responsive; // an array of strings
        }

    } catch (err) {
        console.error(`Failed to test RPCs. Error: ${err.message}`);
        throw err;
    }
}








