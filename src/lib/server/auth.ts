import { Buffer } from "node:buffer";
import type { APIContext } from "astro";
import type { ResourceAuthUser } from "@/types/resources";

type Cookies = APIContext["cookies"];

interface SessionPayload extends ResourceAuthUser {
    sub: string;
    exp: number;
}

interface GitHubUser {
    id: number;
    login: string;
    avatar_url: string;
}

const OWNER_GITHUB_ID = "180516193";
const SESSION_COOKIE = "resource_admin_session";
const OAUTH_STATE_COOKIE = "resource_oauth_state";
const OAUTH_VERIFIER_COOKIE = "resource_oauth_verifier";
const OAUTH_RETURN_COOKIE = "resource_oauth_return";
const OAUTH_ATTEMPT_TTL_SECONDS = 10 * 60;
const SESSION_TTL_SECONDS = 12 * 60 * 60;

const githubClientId =
    process.env.GITHUB_CLIENT_ID ?? import.meta.env.GITHUB_CLIENT_ID;
const githubClientSecret =
    process.env.GITHUB_CLIENT_SECRET ?? import.meta.env.GITHUB_CLIENT_SECRET;
const authSecret = process.env.AUTH_SECRET ?? import.meta.env.AUTH_SECRET;
const explicitCallbackUrl =
    process.env.GITHUB_OAUTH_CALLBACK_URL ??
    import.meta.env.GITHUB_OAUTH_CALLBACK_URL;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function bytesToBase64Url(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString("base64url");
}

function stringToBase64Url(value: string): string {
    return bytesToBase64Url(encoder.encode(value));
}

function base64UrlToBytes(value: string): Uint8Array<ArrayBuffer> {
    const buffer = Buffer.from(value, "base64url");
    const bytes = new Uint8Array(buffer.length);
    bytes.set(buffer);
    return bytes;
}

function randomToken(byteLength = 32): string {
    return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(byteLength)));
}

function isSecure(url: URL): boolean {
    return url.protocol === "https:";
}

function sanitizeReturnPath(value: string | null): string {
    if (!value || !value.startsWith("/") || value.startsWith("//")) {
        return "/resources/";
    }
    return value;
}

function callbackUrl(requestUrl: URL): string {
    return (
        explicitCallbackUrl?.trim() ||
        new URL("/api/auth/callback", requestUrl).toString()
    );
}

async function importSigningKey(): Promise<CryptoKey> {
    if (!authSecret || authSecret.length < 32) {
        throw new Error("AUTH_SECRET must contain at least 32 characters.");
    }

    return crypto.subtle.importKey(
        "raw",
        encoder.encode(authSecret),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign", "verify"],
    );
}

async function sign(value: string): Promise<string> {
    const signature = await crypto.subtle.sign(
        "HMAC",
        await importSigningKey(),
        encoder.encode(value),
    );
    return bytesToBase64Url(new Uint8Array(signature));
}

async function verify(value: string, signature: string): Promise<boolean> {
    try {
        return await crypto.subtle.verify(
            "HMAC",
            await importSigningKey(),
            base64UrlToBytes(signature),
            encoder.encode(value),
        );
    } catch {
        return false;
    }
}

export function isAuthConfigured(): boolean {
    return Boolean(
        githubClientId?.trim() &&
            githubClientSecret?.trim() &&
            authSecret &&
            authSecret.length >= 32,
    );
}

export async function beginGitHubLogin(
    cookies: Cookies,
    requestUrl: URL,
    requestedReturnPath: string | null,
): Promise<URL> {
    const clientId = githubClientId?.trim();
    if (!isAuthConfigured() || !clientId) {
        throw new Error("Resource authentication is not configured.");
    }

    const state = randomToken(24);
    const verifier = randomToken(32);
    const challenge = bytesToBase64Url(
        new Uint8Array(
            await crypto.subtle.digest("SHA-256", encoder.encode(verifier)),
        ),
    );
    const returnPath = sanitizeReturnPath(requestedReturnPath);
    const cookieOptions = {
        httpOnly: true,
        sameSite: "lax" as const,
        secure: isSecure(requestUrl),
        path: "/",
        maxAge: OAUTH_ATTEMPT_TTL_SECONDS,
    };

    cookies.set(OAUTH_STATE_COOKIE, state, cookieOptions);
    cookies.set(OAUTH_VERIFIER_COOKIE, verifier, cookieOptions);
    cookies.set(
        OAUTH_RETURN_COOKIE,
        stringToBase64Url(returnPath),
        cookieOptions,
    );

    const authorizeUrl = new URL("https://github.com/login/oauth/authorize");
    authorizeUrl.searchParams.set("client_id", clientId);
    authorizeUrl.searchParams.set("redirect_uri", callbackUrl(requestUrl));
    authorizeUrl.searchParams.set("scope", "read:user");
    authorizeUrl.searchParams.set("state", state);
    authorizeUrl.searchParams.set("code_challenge", challenge);
    authorizeUrl.searchParams.set("code_challenge_method", "S256");
    authorizeUrl.searchParams.set("allow_signup", "false");
    return authorizeUrl;
}

export function consumeGitHubLoginAttempt(
    cookies: Cookies,
    requestUrl: URL,
): { state?: string; verifier?: string; returnPath: string } {
    const state = cookies.get(OAUTH_STATE_COOKIE)?.value;
    const verifier = cookies.get(OAUTH_VERIFIER_COOKIE)?.value;
    const encodedReturnPath = cookies.get(OAUTH_RETURN_COOKIE)?.value;

    const deleteOptions = {
        httpOnly: true,
        sameSite: "lax" as const,
        secure: isSecure(requestUrl),
        path: "/",
    };
    cookies.delete(OAUTH_STATE_COOKIE, deleteOptions);
    cookies.delete(OAUTH_VERIFIER_COOKIE, deleteOptions);
    cookies.delete(OAUTH_RETURN_COOKIE, deleteOptions);

    let returnPath = "/resources/";
    if (encodedReturnPath) {
        try {
            returnPath = sanitizeReturnPath(
                decoder.decode(base64UrlToBytes(encodedReturnPath)),
            );
        } catch {
            returnPath = "/resources/";
        }
    }

    return { state, verifier, returnPath };
}

export async function exchangeGitHubCode(
    code: string,
    verifier: string,
    requestUrl: URL,
): Promise<GitHubUser> {
    const clientId = githubClientId?.trim();
    const clientSecret = githubClientSecret?.trim();
    if (!isAuthConfigured() || !clientId || !clientSecret) {
        throw new Error("Resource authentication is not configured.");
    }

    const tokenResponse = await fetch(
        "https://github.com/login/oauth/access_token",
        {
            method: "POST",
            headers: {
                accept: "application/json",
                "content-type": "application/x-www-form-urlencoded",
            },
            body: new URLSearchParams({
                client_id: clientId,
                client_secret: clientSecret,
                code,
                code_verifier: verifier,
                redirect_uri: callbackUrl(requestUrl),
            }),
        },
    );
    if (!tokenResponse.ok) {
        throw new Error("GitHub token exchange failed.");
    }

    const tokenBody = (await tokenResponse.json()) as {
        access_token?: string;
        error?: string;
    };
    if (!tokenBody.access_token || tokenBody.error) {
        throw new Error("GitHub did not return an access token.");
    }

    const userResponse = await fetch("https://api.github.com/user", {
        headers: {
            accept: "application/vnd.github+json",
            authorization: `Bearer ${tokenBody.access_token}`,
            "x-github-api-version": "2022-11-28",
        },
    });
    if (!userResponse.ok) {
        throw new Error("Unable to read the GitHub user profile.");
    }

    return (await userResponse.json()) as GitHubUser;
}

export function isResourceOwner(user: GitHubUser): boolean {
    return String(user.id) === OWNER_GITHUB_ID;
}

export async function createOwnerSession(
    cookies: Cookies,
    requestUrl: URL,
    user: GitHubUser,
): Promise<void> {
    const payload: SessionPayload = {
        sub: OWNER_GITHUB_ID,
        login: user.login,
        avatarUrl: user.avatar_url,
        exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
    };
    const encodedPayload = stringToBase64Url(JSON.stringify(payload));
    const signature = await sign(encodedPayload);

    cookies.set(SESSION_COOKIE, `${encodedPayload}.${signature}`, {
        httpOnly: true,
        sameSite: "lax",
        secure: isSecure(requestUrl),
        path: "/",
        maxAge: SESSION_TTL_SECONDS,
    });
}

export async function getOwnerSession(
    cookies: Cookies,
): Promise<ResourceAuthUser | null> {
    if (!isAuthConfigured()) return null;

    const session = cookies.get(SESSION_COOKIE)?.value;
    if (!session) return null;

    const separator = session.lastIndexOf(".");
    if (separator < 1) return null;
    const encodedPayload = session.slice(0, separator);
    const signature = session.slice(separator + 1);
    if (!(await verify(encodedPayload, signature))) return null;

    try {
        const payload = JSON.parse(
            decoder.decode(base64UrlToBytes(encodedPayload)),
        ) as SessionPayload;
        if (
            payload.sub !== OWNER_GITHUB_ID ||
            payload.exp <= Math.floor(Date.now() / 1000) ||
            typeof payload.login !== "string" ||
            typeof payload.avatarUrl !== "string"
        ) {
            return null;
        }
        return { login: payload.login, avatarUrl: payload.avatarUrl };
    } catch {
        return null;
    }
}

export function clearOwnerSession(cookies: Cookies, requestUrl: URL): void {
    cookies.delete(SESSION_COOKIE, {
        httpOnly: true,
        sameSite: "lax",
        secure: isSecure(requestUrl),
        path: "/",
    });
}
