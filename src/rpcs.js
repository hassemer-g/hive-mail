import {
    shuffleArr,
} from "./utils.js";
import { Client } from "./client.js";

const RPCsArr = [
    "https://api.hive.blog",
    "https://api.openhive.network",
    "https://hive-api.arcange.eu",
    "https://rpc.mahdiyari.info",
    "https://hive-api.3speak.tv",
    "https://techcoderx.com",
    "https://api.deathwing.me",
    "https://anyx.io",

    "https://hiveapi.actifit.io",
    "https://api.c0ff33a.uk",
];

async function testRPCs(
    nodes = null,
    shuffleNeeded = true,
    timeoutMs = 3000,
) {
    const sourceNodes = Array.isArray(nodes) && nodes.length
        ? nodes
        : RPCsArr;

    const cleanNodes = sourceNodes
        .filter(n => typeof n === "string")
        .map(n => n.trim())
        .filter(Boolean);

    if (!cleanNodes.length) {
        console.warn(`Warning: no valid RPC nodes provided`);
        return [];
    }

    const testRPC = async (url) => {
        try {
            const client = new Client(url, timeoutMs);

            await client.call(
                "condenser_api",
                "get_version",
                [],
            );

            return url;

        } catch {
            return null;
        }
    };

    const results = await Promise.allSettled(
        cleanNodes.map(testRPC)
    );

    console.log(`RPC probe results:`, results);

    const responsive = results
        .filter(r => r.status === "fulfilled")
        .map(r => r.value)
        .filter(Boolean);

    if (!responsive.length) {
        console.warn(`Warning: no responsive Hive RPC nodes within timeout`);
        return [];
    }

    return shuffleNeeded && responsive.length > 1
        ? shuffleArr(responsive)
        : responsive;
}

export async function getResponsiveNodes(

) {
    let nodes = null;
    for (let i = 0; true; i++) {
        nodes = null;
        try {
            nodes = await testRPCs();
        } catch (err) {

        }
        if (nodes?.length) {
            return nodes;
        } else {
            if (i < 9) {
                console.warn(`RPC test returned no responsive nodes. Retrying... (initiating now attempt ${i + 2} of 10)`);
            } else {
                throw new Error(`No Hive node is responsive right now`);
            }
        }
    }
}

function timeout(ms) {
    return new Promise((_, reject) =>
        setTimeout(() => reject(new Error(`Timed out after ${ms} ms`)), ms)
    );
}
export async function callHiveNode(
    method,
    input = null,
    RPCs = null,
    api = "condenser_api",
    timeoutMs = 3000,
) {
    let nodes;
    if (Array.isArray(RPCs) && RPCs.length) {
        nodes = RPCs;
    } else {
        nodes = await getResponsiveNodes();
    }
    let client = new Client(nodes);

    for (let i = 0; true; i++) {
        try {
            const props = await Promise.race([
                Promise.any(
                    nodes.map(RPC =>
                        client.call(
                            api,
                            method,
                            input === null ? [] : [input],
                            RPC,
                        ).then(result => {
                            if (!result) {
                                throw new Error(`Falsy response from ${RPC}`);
                            }
                            return result;
                        }).catch(err => {
                            console.error(`
Call failed on node "${RPC}". Error: ${err?.message ? err.message : String(err)}
`);
                            throw err;
                        })
                    )
                ),
                timeout(timeoutMs),
            ]);

            return props;

        } catch (err) {
            if (i > 8) {
                throw new Error(`
==============================
All retrieval attempts failed!
==============================
`);
            }

            console.log(`Retrying... (initiating now attempt ${i + 2} of 10)`);
            nodes = await getResponsiveNodes();
            client = new Client(nodes);
        }
    }
}

export let NODES = null;
let firstTime = true;
export async function getRespNodes(
    enforceAnew = false,
) {
    if (
        enforceAnew
        || firstTime
        || !Array.isArray(NODES)
        || !NODES.length
    ) {

        console.log(`
Testing Hive nodes and ${firstTime ? "" : "re-"}building "NODES"${firstTime ? " for the first time" : ""}...
`);

        firstTime = false;
        NODES = await getResponsiveNodes();

    } else {
        if (NODES.length > 1) {
            NODES = shuffleArr(NODES);
        }
    }
}
