import { type HandleUploadBody, handleUpload } from "@vercel/blob/client";
import type { APIRoute } from "astro";
import {
    MAX_PDF_COVER_SIZE,
    MAX_PDF_SIZE,
    UPLOAD_TOKEN_TTL,
} from "@/constants/resources";
import { getOwnerSession } from "@/lib/server/auth";
import { isSameOrigin, jsonResponse } from "@/lib/server/http";
import {
    assertUniqueResourceContent,
    bookPathname,
    coverPathname,
    deleteUploadedBlob,
    isBlobConfigured,
    parseUploadRequest,
    saveResourceMetadata,
    verifyJpegBlob,
    verifyPdfBlob,
} from "@/lib/server/resources";

export const prerender = false;

const blobToken =
    process.env.BLOB_READ_WRITE_TOKEN ?? import.meta.env.BLOB_READ_WRITE_TOKEN;

export const POST: APIRoute = async ({ cookies, request }) => {
    if (!isBlobConfigured() || !blobToken) {
        return jsonResponse({ error: "资源存储尚未配置" }, { status: 503 });
    }

    let body: HandleUploadBody;
    try {
        body = (await request.json()) as HandleUploadBody;
    } catch {
        return jsonResponse({ error: "请求内容无效" }, { status: 400 });
    }

    if (body.type === "blob.generate-client-token") {
        if (!isSameOrigin(request)) {
            return jsonResponse({ error: "请求来源无效" }, { status: 403 });
        }
        if (!(await getOwnerSession(cookies))) {
            return jsonResponse(
                { error: "请先使用 GitHub 登录" },
                { status: 401 },
            );
        }
    }

    try {
        const result = await handleUpload({
            token: blobToken,
            request,
            body,
            onBeforeGenerateToken: async (pathname, clientPayload) => {
                const uploadRequest = parseUploadRequest(clientPayload);
                const expectedPathname =
                    uploadRequest.asset === "cover"
                        ? coverPathname(uploadRequest.id)
                        : bookPathname(uploadRequest.id);
                if (pathname !== expectedPathname) {
                    throw new Error("Upload pathname is invalid.");
                }
                if (uploadRequest.asset === "book") {
                    await assertUniqueResourceContent(
                        uploadRequest.id,
                        uploadRequest.contentSha256,
                        uploadRequest.fileSize,
                    );
                }

                return {
                    allowedContentTypes: [
                        uploadRequest.asset === "cover"
                            ? "image/jpeg"
                            : "application/pdf",
                    ],
                    maximumSizeInBytes:
                        uploadRequest.asset === "cover"
                            ? MAX_PDF_COVER_SIZE
                            : MAX_PDF_SIZE,
                    validUntil: Date.now() + UPLOAD_TOKEN_TTL,
                    addRandomSuffix: false,
                    allowOverwrite: false,
                    cacheControlMaxAge: 365 * 24 * 60 * 60,
                    tokenPayload: JSON.stringify(uploadRequest),
                };
            },
            onUploadCompleted: async ({ blob, tokenPayload }) => {
                const uploadRequest = parseUploadRequest(tokenPayload ?? null);
                if (uploadRequest.asset === "cover") {
                    if (
                        blob.pathname !== coverPathname(uploadRequest.id) ||
                        blob.contentType !== "image/jpeg"
                    ) {
                        await deleteUploadedBlob(blob.pathname);
                        throw new Error(
                            "Uploaded blob did not match the cover token.",
                        );
                    }

                    if (!(await verifyJpegBlob(blob.url))) {
                        await deleteUploadedBlob(blob.pathname);
                        throw new Error(
                            "Uploaded file does not contain a JPEG header.",
                        );
                    }
                    return;
                }

                const { asset: _asset, ...payload } = uploadRequest;
                if (
                    blob.pathname !== bookPathname(payload.id) ||
                    blob.contentType !== "application/pdf"
                ) {
                    await deleteUploadedBlob(blob.pathname);
                    throw new Error(
                        "Uploaded blob did not match the PDF token.",
                    );
                }

                try {
                    if (!(await verifyPdfBlob(blob.url, payload.fileSize))) {
                        throw new Error(
                            "Uploaded file does not match its PDF metadata.",
                        );
                    }
                    await saveResourceMetadata(payload, blob.pathname);
                } catch (error) {
                    await deleteUploadedBlob(blob.pathname);
                    throw error;
                }
            },
        });

        return jsonResponse(result, {
            headers: { "cache-control": "private, no-store" },
        });
    } catch (error) {
        console.error("Resource upload failed", error);
        const message =
            body.type === "blob.generate-client-token" && error instanceof Error
                ? error.message
                : "资源上传处理失败";
        return jsonResponse({ error: message }, { status: 400 });
    }
};
