import type { APIRoute } from "astro";
import { jsonResponse } from "@/lib/server/http";
import { isBlobConfigured, listResources } from "@/lib/server/resources";
import type { ResourceListResponse } from "@/types/resources";

export const prerender = false;

export const GET: APIRoute = async () => {
    if (!isBlobConfigured()) {
        const response: ResourceListResponse = {
            configured: false,
            resources: [],
        };
        return jsonResponse(response, {
            headers: { "cache-control": "no-store" },
        });
    }

    try {
        const response: ResourceListResponse = {
            configured: true,
            resources: await listResources(),
        };
        return jsonResponse(response, {
            headers: { "cache-control": "no-store" },
        });
    } catch (error) {
        console.error("Unable to list resource PDFs", error);
        return jsonResponse(
            { error: "资源列表暂时无法读取" },
            {
                status: 503,
                headers: { "cache-control": "no-store" },
            },
        );
    }
};
