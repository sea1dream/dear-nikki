import type { APIRoute } from "astro";
import { beginGitHubLogin } from "@/lib/server/auth";

export const prerender = false;

export const GET: APIRoute = async ({ cookies, request, redirect }) => {
    const requestUrl = new URL(request.url);

    try {
        const authorizeUrl = await beginGitHubLogin(
            cookies,
            requestUrl,
            requestUrl.searchParams.get("returnTo"),
        );
        return redirect(authorizeUrl.toString(), 302);
    } catch {
        return redirect("/resources/?auth=not-configured", 302);
    }
};
