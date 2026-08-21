import { createHash } from "node:crypto";
import { del, get, type ListBlobResultBlob, list, put } from "@vercel/blob";
import { MAX_PDF_SIZE } from "@/constants/resources";
import type {
    ResourceItem,
    ResourceMetadata,
    ResourceUploadPayload,
    ResourceUploadRequest,
} from "@/types/resources";

export const RESOURCE_BOOK_PREFIX = "resources/books/";
export const RESOURCE_COVER_PREFIX = "resources/covers/";
export const RESOURCE_METADATA_PREFIX = "resources/meta/";
export const RESOURCE_HASH_PREFIX = "resources/hashes/";

const blobToken =
    process.env.BLOB_READ_WRITE_TOKEN ?? import.meta.env.BLOB_READ_WRITE_TOKEN;
const resourceIdPattern =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[4-7][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const sha256Pattern = /^[0-9a-f]{64}$/u;
const hashClaimStaleAfter = 6 * 60 * 60 * 1000;

interface ResourceHashClaim {
    version: 1;
    id: string;
    contentSha256: string;
    claimedAt: string;
}

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

function hashPathname(contentSha256: string): string {
    return `${RESOURCE_HASH_PREFIX}${contentSha256}.json`;
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
    const contentSha256 = cleanText(
        input.contentSha256,
        "contentSha256",
        64,
        true,
    ).toLocaleLowerCase("en-US");
    if (!sha256Pattern.test(contentSha256)) {
        throw new Error("PDF content hash is invalid.");
    }
    const fileSize = input.fileSize;
    if (
        typeof fileSize !== "number" ||
        !Number.isSafeInteger(fileSize) ||
        fileSize < 1 ||
        fileSize > MAX_PDF_SIZE
    ) {
        throw new Error("PDF file size is invalid.");
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
        contentSha256,
        fileSize,
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
        (metadata.contentSha256 === undefined ||
            (typeof metadata.contentSha256 === "string" &&
                sha256Pattern.test(metadata.contentSha256))) &&
        typeof metadata.uploadedAt === "string" &&
        typeof metadata.pathname === "string"
    );
}

function isHashClaim(value: unknown): value is ResourceHashClaim {
    if (!value || typeof value !== "object") return false;
    const claim = value as Partial<ResourceHashClaim>;
    return (
        claim.version === 1 &&
        typeof claim.id === "string" &&
        isResourceId(claim.id) &&
        typeof claim.contentSha256 === "string" &&
        sha256Pattern.test(claim.contentSha256) &&
        typeof claim.claimedAt === "string"
    );
}

async function readJsonBlob(pathname: string): Promise<unknown | null> {
    const result = await get(pathname, {
        ...blobOptions(),
        access: "public",
    });
    if (!result || result.statusCode !== 200) return null;
    return JSON.parse(await new Response(result.stream).text());
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
        const parsed = await readJsonBlob(blob.pathname);
        return isMetadata(parsed) ? parsed : null;
    } catch {
        return null;
    }
}

async function readMetadataById(id: string): Promise<ResourceMetadata | null> {
    const parsed = await readJsonBlob(metadataPathname(id));
    return isMetadata(parsed) ? parsed : null;
}

async function readHashClaim(
    contentSha256: string,
): Promise<ResourceHashClaim | null> {
    const parsed = await readJsonBlob(hashPathname(contentSha256));
    return isHashClaim(parsed) ? parsed : null;
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
                contentSha256: item?.contentSha256,
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

export async function verifyPdfBlob(
    url: string,
    expectedSize: number,
): Promise<boolean> {
    const response = await fetch(url, {
        headers: { range: "bytes=0-1023" },
        cache: "no-store",
        signal: AbortSignal.timeout(15_000),
    });
    if (response.status !== 206) {
        await response.body?.cancel();
        return false;
    }
    const contentRange = response.headers.get("content-range");
    const totalSize = contentRange?.match(/\/(\d+)$/u)?.[1];
    if (!totalSize || Number(totalSize) !== expectedSize) {
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

function duplicateContentError(resource?: ResourceItem): Error {
    return new Error(
        resource
            ? `这个 PDF 与资源库中的《${resource.title}》内容完全相同，不能重复上传`
            : "资源库中已有内容完全相同的 PDF，不能重复上传",
    );
}

async function claimResourceHash(
    id: string,
    contentSha256: string,
): Promise<boolean> {
    const existing = await readHashClaim(contentSha256);
    if (existing) {
        if (existing.id === id) return false;
        throw duplicateContentError();
    }

    const claim: ResourceHashClaim = {
        version: 1,
        id,
        contentSha256,
        claimedAt: new Date().toISOString(),
    };
    try {
        await put(hashPathname(contentSha256), JSON.stringify(claim), {
            ...blobOptions(),
            access: "public",
            addRandomSuffix: false,
            allowOverwrite: false,
            contentType: "application/json; charset=utf-8",
            cacheControlMaxAge: 60,
        });
        return true;
    } catch (error) {
        const winner = await readHashClaim(contentSha256);
        if (winner) {
            if (winner.id === id) return false;
            throw duplicateContentError();
        }
        throw error;
    }
}

async function releaseResourceHash(
    id: string,
    contentSha256: string,
): Promise<void> {
    const claim = await readHashClaim(contentSha256);
    if (claim?.id === id) {
        await del(hashPathname(contentSha256), blobOptions());
    }
}

async function sha256RemoteBlob(url: string): Promise<string> {
    const response = await fetch(url, {
        cache: "no-store",
        signal: AbortSignal.timeout(5 * 60 * 1000),
    });
    if (!response.ok || !response.body) {
        await response.body?.cancel();
        throw new Error("无法校验已有 PDF 的内容，请稍后重试");
    }

    const hasher = createHash("sha256");
    const reader = response.body.getReader();
    try {
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            hasher.update(value);
        }
    } finally {
        reader.releaseLock();
    }
    return hasher.digest("hex");
}

async function saveContentHash(
    resource: ResourceItem,
    contentSha256: string,
): Promise<void> {
    const metadata: ResourceMetadata = {
        version: 1,
        id: resource.id,
        title: resource.title,
        author: resource.author,
        description: resource.description,
        originalFilename: resource.originalFilename,
        contentSha256,
        uploadedAt: resource.uploadedAt,
        pathname: resource.pathname,
    };
    await put(metadataPathname(resource.id), JSON.stringify(metadata), {
        ...blobOptions(),
        access: "public",
        addRandomSuffix: false,
        allowOverwrite: true,
        contentType: "application/json; charset=utf-8",
        cacheControlMaxAge: 60,
    });
}

export async function assertUniqueResourceContent(
    id: string,
    contentSha256: string,
    fileSize: number,
): Promise<void> {
    const resources = await listResources();
    const existingClaim = await readHashClaim(contentSha256);
    if (existingClaim && existingClaim.id !== id) {
        const duplicate = resources.find(
            (resource) => resource.id === existingClaim.id,
        );
        if (duplicate) throw duplicateContentError(duplicate);

        const claimedAt = Date.parse(existingClaim.claimedAt);
        if (
            Number.isFinite(claimedAt) &&
            Date.now() - claimedAt < hashClaimStaleAfter
        ) {
            throw duplicateContentError();
        }
        await releaseResourceHash(
            existingClaim.id,
            existingClaim.contentSha256,
        );
    }

    const knownDuplicate = resources.find(
        (resource) =>
            resource.id !== id && resource.contentSha256 === contentSha256,
    );
    if (knownDuplicate) {
        try {
            await claimResourceHash(
                knownDuplicate.id,
                knownDuplicate.contentSha256 ?? contentSha256,
            );
        } catch {
            // A claim for another copy still proves that this content exists.
        }
        throw duplicateContentError(knownDuplicate);
    }

    const legacyCandidates = resources.filter(
        (resource) =>
            resource.id !== id &&
            !resource.contentSha256 &&
            resource.size === fileSize,
    );
    for (const resource of legacyCandidates) {
        const existingSha256 = await sha256RemoteBlob(resource.url);
        await saveContentHash(resource, existingSha256);
        if (existingSha256 === contentSha256) {
            try {
                await claimResourceHash(resource.id, existingSha256);
            } catch {
                // The duplicate is rejected even if another resource owns the claim.
            }
            throw duplicateContentError(resource);
        }
    }
}

export async function saveResourceMetadata(
    payload: ResourceUploadPayload,
    pathname: string,
): Promise<void> {
    const { fileSize: _fileSize, ...metadataPayload } = payload;
    const metadata: ResourceMetadata = {
        version: 1,
        ...metadataPayload,
        uploadedAt: new Date().toISOString(),
        pathname,
    };
    const claimed = await claimResourceHash(payload.id, payload.contentSha256);
    try {
        await put(metadataPathname(payload.id), JSON.stringify(metadata), {
            ...blobOptions(),
            access: "public",
            addRandomSuffix: false,
            allowOverwrite: true,
            contentType: "application/json; charset=utf-8",
            cacheControlMaxAge: 60,
        });
    } catch (error) {
        if (claimed) {
            await releaseResourceHash(payload.id, payload.contentSha256);
        }
        throw error;
    }
}

export async function deleteUploadedBlob(pathname: string): Promise<void> {
    await del(pathname, blobOptions());
}

export async function deleteResource(id: string): Promise<void> {
    if (!isResourceId(id)) throw new Error("Resource id is invalid.");
    const metadata = await readMetadataById(id);
    await del(
        [bookPathname(id), coverPathname(id), metadataPathname(id)],
        blobOptions(),
    );
    if (metadata?.contentSha256) {
        await releaseResourceHash(id, metadata.contentSha256);
    }
}
