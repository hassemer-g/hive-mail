

function readFileAsUint8Array(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(new Uint8Array(reader.result));
        reader.onerror = () => reject(reader.error);
        reader.readAsArrayBuffer(file);
    });
}

export async function processFileUpload(file) {
    let fileBytes;
    try {

        fileBytes = await readFileAsUint8Array(file);
    } catch (err) {

        return null;
    }

    if (
        fileBytes instanceof Uint8Array
        && fileBytes.length
    ) {

        return fileBytes;
    } else {

        return null;
    }
}

function uint8ArrayToBlob(u8) {
    if (!(u8 instanceof Uint8Array)) { throw new TypeError("Expected Uint8Array"); }
    return new Blob(
        [
            u8.buffer.slice(
                u8.byteOffset,
                u8.byteOffset + u8.byteLength,
            ),
        ],
        { type: "application/octet-stream" },
    );
}
function normalizeToBlob(content) {
    if (content instanceof Blob) { return content; }
    if (content instanceof Uint8Array) { return uint8ArrayToBlob(content); }
    if (content instanceof ArrayBuffer) { return new Blob([content], { type: "application/octet-stream" }); }
    if (typeof content === "string") { return new Blob([content], { type: "text/plain;charset=utf-8" }); }
    throw new TypeError("Unsupported content type");
}
export async function saveToFile(content, suggestedName = "download") {
    const blob = normalizeToBlob(content);

    if (window.showSaveFilePicker) {
        const handle = await window.showSaveFilePicker({ suggestedName });
        const writable = await handle.createWritable();
        await writable.write(blob);
        await writable.close();
        return;
    }

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = suggestedName;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}
