import { createSHA256 } from "hash-wasm";

const HASH_CHUNK_SIZE = 8 * 1024 ** 2;

export async function sha256File(
    file: Blob,
    onProgress?: (percentage: number) => void,
): Promise<string> {
    const hasher = await createSHA256();
    hasher.init();

    let lastPercentage = -1;
    for (let offset = 0; offset < file.size; offset += HASH_CHUNK_SIZE) {
        const end = Math.min(offset + HASH_CHUNK_SIZE, file.size);
        const chunk = new Uint8Array(
            await file.slice(offset, end).arrayBuffer(),
        );
        hasher.update(chunk);

        const percentage = Math.round((end / file.size) * 100);
        if (percentage !== lastPercentage) {
            lastPercentage = percentage;
            onProgress?.(percentage);
        }
    }

    return hasher.digest("hex");
}
