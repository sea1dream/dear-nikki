import type { APIRoute } from "astro";
import { clearOwnerSession } from "@/lib/server/auth";
import { isSameOrigin, jsonResponse } from "@/lib/server/http";

export const prerender = false;

export const POST: APIRoute = ({ cookies, request }) => {
    if (!isSameOrigin(request)) {
        return jsonResponse({ error: "请求来源无效" }, { status: 403 });
    }

    clearOwnerSession(cookies, new URL(request.url));
    return jsonResponse(
        { success: true },
        { headers: { "cache-control": "private, no-store" } },
    );
};
