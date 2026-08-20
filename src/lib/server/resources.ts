import { del, get, type ListBlobResultBlob, list, put } from "@vercel/blob";
import type {
    ResourceItem,
    ResourceMetadata,
    ResourceUploadPayload,
    ResourceUploadRequest,
} from "@/types/resources";

export const RESOURCE_BOOK_PREFIX = "resources/books/";
export const RESOURCE_COVER_PREFIX = "resources/covers/";
export const RESOURCE_METADATA_PREFIX = "resources/meta/";

const blobToken =
    process.env.BLOB_READ_WRITE_TOKEN ?? import.meta.env.BLOB_READ_WRITE_TOKEN;
const resourceIdPattern =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[4-7][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;

function blobOptions(): { token?: string } {
    return blobToken ? { token: blobToken } : {};
}

function cleanText(
    value: unknown,
    fieldName: string,
    maximumLength: number,
    required = false,
): string {
    if (typeof value !== "string") {
        if (required) throw new Error(`${fieldName} is required.`);
        return "";
    }

    const cleaned = value.trim();
    if (required && !cleaned) throw new Error(`${fieldName} is required.`);
    if (cleaned.length > maximumLength) {
        throw new Error(`${fieldName} is too long.`);
    }
    return cleaned;
}

export function isBlobConfigured(): boolean {
    return Boolean(blobToken);
}

export function isResourceId(value: string): boolean {
    return resourceIdPattern.test(value);
}

export function bookPathname(id: string): string {
    return `${RESOURCE_BOOK_PREFIX}${id}.pdf`;
}

export function coverPathname(id: string): string {
    return `${RESOURCE_COVER_PREFIX}${id}.jpg`;
}

export function metadataPathname(id: string): string {
    return `${RESOURCE_METADATA_PREFIX}${id}.json`;
}

export function parseUploadRequest(
    value: string | null,
): ResourceUploadRequest {
    if (!value) throw new Error("Upload metadata is missing.");

    let parsed: unknown;
    try {
        parsed = JSON.parse(value);
    } catch {
        throw new Error("Upload metadata is invalid.");
    }
    if (!parsed || typeof parsed !== "object") {
        throw new Error("Upload metadata is invalid.");
    }

    const input = parsed as Record<string, unknown>;
    const id = cleanText(input.id, "id", 36, true);
    if (!isResourceId(id)) throw new Error("Resource id is invalid.");
    const asset = input.asset === undefined ? "book" : input.asset;
    if (asset !== "book" && asset !== "cover") {
        throw new Error("Upload asset type is invalid.");
    }

    return {
        asset,
        id,
        title: cleanText(input.title, "title", 160, true),
        author: cleanText(input.author, "author", 120),
        description: cleanText(input.description, "description", 1000),
        originalFilename: cleanText(
            input.originalFilename,
            "originalFilename",
            255,
            true,
        ),
    };
}

function isMetadata(value: unknown): value is ResourceMetadata {
    if (!value || typeof value !== "object") return false;
    const metadata = value as Partial<ResourceMetadata>;
    return (
        metadata.version === 1 &&
        typeof metadata.id === "string" &&
        isResourceId(metadata.id) &&
        typeof metadata.title === "string" &&
        typeof metadata.author === "string" &&
        typeof metadata.description === "string" &&
        typeof metadata.originalFilename === "string" &&
        typeof metadata.uploadedAt === "string" &&
        typeof metadata.pathname === "string"
    );
}

async function listAll(prefix: string): Promise<ListBlobResultBlob[]> {
    const blobs: ListBlobResultBlob[] = [];
    let cursor: string | undefined;

    do {
        const page = await list({
            ...blobOptions(),
            prefix,
            cursor,
            limit: 1000,
        });
        blobs.push(...page.blobs);
        cursor = page.hasMore ? page.cursor : undefined;
    } while (cursor);

    return blobs;
}

async function readMetadata(
    blob: ListBlobResultBlob,
): Promise<ResourceMetadata | null> {
    try {
        const result = await get(blob.pathname, {
            ...blobOptions(),
            access: "public",
        });
        if (!result || result.statusCode !== 200) return null;
        const parsed = JSON.parse(await new Response(result.stream).text());
        return isMetadata(parsed) ? parsed : null;
    } catch {
        return null;
    }
}

function idFromBookPathname(pathname: string): string | null {
    const match = pathname.match(/^resources\/books\/([0-9a-f-]{36})\.pdf$/iu);
    return match?.[1] && isResourceId(match[1]) ? match[1] : null;
}

function idFromCoverPathname(pathname: string): string | null {
    const match = pathname.match(/^resources\/covers\/([0-9a-f-]{36})\.jpg$/iu);
    return match?.[1] && isResourceId(match[1]) ? match[1] : null;
}

export async function listResources(): Promise<ResourceItem[]> {
    const [bookBlobs, coverBlobs, metadataBlobs] = await Promise.all([
        listAll(RESOURCE_BOOK_PREFIX),
        listAll(RESOURCE_COVER_PREFIX),
        listAll(RESOURCE_METADATA_PREFIX),
    ]);
    const metadata = await Promise.all(metadataBlobs.map(readMetadata));
    const metadataById = new Map(
        metadata
            .filter((item): item is ResourceMetadata => item !== null)
            .map((item) => [item.id, item]),
    );
    const coverById = new Map(
        coverBlobs.flatMap((blob) => {
            const id = idFromCoverPathname(blob.pathname);
            return id ? [[id, blob] as const] : [];
        }),
    );

    return bookBlobs
        .map((blob): ResourceItem | null => {
            const id = idFromBookPathname(blob.pathname);
            if (!id) return null;
            const item = metadataById.get(id);
            const uploadedAt =
                item?.uploadedAt ?? blob.uploadedAt.toISOString();

            return {
                version: 1,
                id,
                title: item?.title || "未命名 PDF",
                author: item?.author || "",
                description: item?.description || "",
                originalFilename: item?.originalFilename || `${id}.pdf`,
                uploadedAt,
                pathname: blob.pathname,
                url: blob.url,
                downloadUrl: blob.downloadUrl,
                size: blob.size,
                coverUrl: coverById.get(id)?.url,
            };
        })
        .filter((item): item is ResourceItem => item !== null)
        .sort(
            (left, right) =>
                Date.parse(right.uploadedAt) - Date.parse(left.uploadedAt),
        );
}

export async function verifyPdfBlob(url: string): Promise<boolean> {
    const response = await fetch(url, {
        headers: { range: "bytes=0-1023" },
        cache: "no-store",
        signal: AbortSignal.timeout(15_000),
    });
    if (response.status !== 206) {
        await response.body?.cancel();
        return false;
    }
    const header = decoder.decode(await response.arrayBuffer());
    return header.includes("%PDF-");
}

export async function verifyJpegBlob(url: string): Promise<boolean> {
    const response = await fetch(url, {
        headers: { range: "bytes=0-2" },
        cache: "no-store",
        signal: AbortSignal.timeout(15_000),
    });
    if (response.status !== 206) {
        await response.body?.cancel();
        return false;
    }
    const header = new Uint8Array(await response.arrayBuffer());
    return header[0] === 0xff && header[1] === 0xd8 && header[2] === 0xff;
}

const decoder = new TextDecoder("latin1");

export async function saveResourceMetadata(
    payload: ResourceUploadPayload,
    pathname: string,
): Promise<void> {
    const metadata: ResourceMetadata = {
        version: 1,
        ...payload,
        uploadedAt: new Date().toISOString(),
        pathname,
    };
    await put(metadataPathname(payload.id), JSON.stringify(metadata), {
        ...blobOptions(),
        access: "public",
        addRandomSuffix: false,
        allowOverwrite: false,
        contentType: "application/json; charset=utf-8",
        cacheControlMaxAge: 60,
    });
}

export async function deleteUploadedBlob(pathname: string): Promise<void> {
    await del(pathname, blobOptions());
}

export async function deleteResource(id: string): Promise<void> {
    if (!isResourceId(id)) throw new Error("Resource id is invalid.");
    await del(
        [bookPathname(id), coverPathname(id), metadataPathname(id)],
        blobOptions(),
    );
}
