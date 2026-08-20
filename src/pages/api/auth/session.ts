import type { APIRoute } from "astro";
import { getOwnerSession, isAuthConfigured } from "@/lib/server/auth";
import { jsonResponse } from "@/lib/server/http";
import type { ResourceAuthResponse } from "@/types/resources";

export const prerender = false;

export const GET: APIRoute = async ({ cookies }) => {
    const user = await getOwnerSession(cookies);
    const response: ResourceAuthResponse = {
        configured: isAuthConfigured(),
        authenticated: user !== null,
        ...(user ? { user } : {}),
    };

    return jsonResponse(response, {
        headers: { "cache-control": "private, no-store" },
    });
};
