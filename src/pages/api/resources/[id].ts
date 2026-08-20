import type { APIRoute } from "astro";
import { getOwnerSession } from "@/lib/server/auth";
import { isSameOrigin, jsonResponse } from "@/lib/server/http";
import {
    deleteResource,
    isBlobConfigured,
    isResourceId,
} from "@/lib/server/resources";

export const prerender = false;

export const DELETE: APIRoute = async ({ cookies, params, request }) => {
    if (!isSameOrigin(request)) {
        return jsonResponse({ error: "请求来源无效" }, { status: 403 });
    }
    if (!(await getOwnerSession(cookies))) {
        return jsonResponse({ error: "请先使用 GitHub 登录" }, { status: 401 });
    }
    if (!isBlobConfigured()) {
        return jsonResponse({ error: "资源存储尚未配置" }, { status: 503 });
    }

    const id = params.id;
    if (!id || !isResourceId(id)) {
        return jsonResponse({ error: "资源编号无效" }, { status: 400 });
    }

    try {
        await deleteResource(id);
        return jsonResponse(
            { success: true },
            { headers: { "cache-control": "private, no-store" } },
        );
    } catch (error) {
        console.error("Unable to delete resource PDF", error);
        return jsonResponse({ error: "删除失败，请稍后重试" }, { status: 500 });
    }
};
