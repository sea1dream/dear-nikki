import type { APIRoute } from "astro";
import {
    consumeGitHubLoginAttempt,
    createOwnerSession,
    exchangeGitHubCode,
    isAuthConfigured,
    isResourceOwner,
} from "@/lib/server/auth";

export const prerender = false;

function resultUrl(origin: string, returnPath: string, result: string): string {
    const url = new URL(returnPath, origin);
    url.searchParams.set("auth", result);
    return url.toString();
}

export const GET: APIRoute = async ({ cookies, request, redirect }) => {
    const requestUrl = new URL(request.url);
    const attempt = consumeGitHubLoginAttempt(cookies, requestUrl);
    const error = requestUrl.searchParams.get("error");
    const code = requestUrl.searchParams.get("code");
    const state = requestUrl.searchParams.get("state");

    if (!isAuthConfigured()) {
        return redirect(
            resultUrl(requestUrl.origin, attempt.returnPath, "not-configured"),
            302,
        );
    }
    if (error) {
        return redirect(
            resultUrl(requestUrl.origin, attempt.returnPath, "cancelled"),
            302,
        );
    }
    if (!code || !state || !attempt.state || !attempt.verifier) {
        return redirect(
            resultUrl(requestUrl.origin, attempt.returnPath, "invalid"),
            302,
        );
    }
    if (state !== attempt.state) {
        return redirect(
            resultUrl(requestUrl.origin, attempt.returnPath, "invalid"),
            302,
        );
    }

    try {
        const user = await exchangeGitHubCode(
            code,
            attempt.verifier,
            requestUrl,
        );
        if (!isResourceOwner(user)) {
            return redirect(
                resultUrl(requestUrl.origin, attempt.returnPath, "forbidden"),
                302,
            );
        }

        await createOwnerSession(cookies, requestUrl, user);
        return redirect(
            resultUrl(requestUrl.origin, attempt.returnPath, "success"),
            302,
        );
    } catch (error) {
        console.error("GitHub OAuth callback failed", error);
        return redirect(
            resultUrl(requestUrl.origin, attempt.returnPath, "failed"),
            302,
        );
    }
};
