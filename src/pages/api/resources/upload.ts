import { type HandleUploadBody, handleUpload } from "@vercel/blob/client";
import type { APIRoute } from "astro";
import { getOwnerSession } from "@/lib/server/auth";
import { isSameOrigin, jsonResponse } from "@/lib/server/http";
import {
    bookPathname,
    deleteUploadedBlob,
    isBlobConfigured,
    MAX_PDF_SIZE,
    parseUploadPayload,
    saveResourceMetadata,
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
                const payload = parseUploadPayload(clientPayload);
                if (pathname !== bookPathname(payload.id)) {
                    throw new Error("Upload pathname is invalid.");
                }

                return {
                    allowedContentTypes: ["application/pdf"],
                    maximumSizeInBytes: MAX_PDF_SIZE,
                    validUntil: Date.now() + 15 * 60 * 1000,
                    addRandomSuffix: false,
                    allowOverwrite: false,
                    cacheControlMaxAge: 365 * 24 * 60 * 60,
                    tokenPayload: JSON.stringify(payload),
                };
            },
            onUploadCompleted: async ({ blob, tokenPayload }) => {
                const payload = parseUploadPayload(tokenPayload ?? null);
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
                    if (!(await verifyPdfBlob(blob.url))) {
                        throw new Error(
                            "Uploaded file does not contain a PDF header.",
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
        console.error("Resource PDF upload failed", error);
        const message =
            body.type === "blob.generate-client-token" && error instanceof Error
                ? error.message
                : "PDF 上传处理失败";
        return jsonResponse({ error: message }, { status: 400 });
    }
};
