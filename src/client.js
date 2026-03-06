import {
    shuffleArr,
} from "./utils.js";

export class Client {
    constructor(
        ADDRESSES,
        TIME_OUT = 3000,
    ) {
        if (
            !(Array.isArray(ADDRESSES) && ADDRESSES.length)
            && !(typeof ADDRESSES === "string" && ADDRESSES.trim())
        ) {
            throw new Error(`"Client" requires at least one RPC address`);
        }
        if (
            !Number.isSafeInteger(TIME_OUT)
        ) {
            throw new Error(`Timeout for "Client" must be a safe integer`);
        }

        this.addresses = Array.isArray(ADDRESSES)
            ? [...ADDRESSES]
            : [ADDRESSES];

        this.timeoutMs = TIME_OUT || 3000;

    }

    async call(
        api,
        method,
        params,
        node = undefined,
        timeout = undefined,
    ) {
        const body = JSON.stringify({
            jsonrpc: "2.0",
            id: Math.floor(Math.random() * 1e9),
            method: `${api}.${method}`,
            params,
        });

        const timeoutMs = timeout || this.timeoutMs;

        let signal;
        let timeoutId;

        const hasNativeTimeout =
            typeof AbortSignal !== "undefined" &&
            typeof AbortSignal.timeout === "function";

        if (hasNativeTimeout) {
            signal = AbortSignal.timeout(timeoutMs);

        } else {
            const controller = new AbortController();

            timeoutId = setTimeout(() => {
                controller.abort();
            }, timeoutMs);

            signal = controller.signal;
        }

try {

            const url = node || shuffleArr([...this.addresses])[0];

            const res = await fetch(url, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",

                },
                body,

                signal,
            });

            if (!res) {
                throw new Error(`Call to ${url} failed`);
            }

            if (!res.ok) {
                throw new Error(`HTTP ${res.status} from ${url}`);
            }

            const json = await res.json();

            if (!json) {
                throw new Error(`Invalid data received from ${url}`);
            }

            if (json.error) {
                throw new Error(json.error.message || (JSON.stringify(json.error) || (String(json.error) || "RPC error")));
            }

            if (json.result) {
                return json.result;
            } else {
                throw new Error(`Invalid result received from ${url}`);
            }

        } catch (err) {
            if (err?.name === "AbortError") {
                throw new Error(`RPC call timed out after ${timeoutMs} ms`);
            }
            throw err;

        } finally {
            clearTimeout(timeoutId);
        }
    }

    async broadcast(
        tx,
        node = undefined,
        timeout = undefined,
    ) {
        if (
            !tx
            || typeof tx !== "object"
            || !tx.transaction
            || typeof tx.transaction !== "object"
        ) {
            throw new Error("Invalid transaction object");
        }

        const trx = tx.transaction;

        if (
            !Array.isArray(trx.operations)
            || !trx.operations.length
            || !Array.isArray(trx.signatures)
            || !trx.signatures.length
        ) {
            throw new Error("Transaction has no operations or signatures");
        }

        const timeoutMs = Math.max(
            60000,
            timeout || 0,
        );

        await this.call(

            "condenser_api",
            "broadcast_transaction",
            [trx],
            node,
            timeoutMs,
        );
        return { tx_id: tx.txId || (tx.id || tx.tx_id) };
    }
}
