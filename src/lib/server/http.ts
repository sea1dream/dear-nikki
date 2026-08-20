export function jsonResponse(
    body: unknown,
    options: { status?: number; headers?: HeadersInit } = {},
): Response {
    const headers = new Headers(options.headers);
    headers.set("content-type", "application/json; charset=utf-8");

    return new Response(JSON.stringify(body), {
        status: options.status ?? 200,
        headers,
    });
}

export function isSameOrigin(request: Request): boolean {
    const origin = request.headers.get("origin");
    return origin !== null && origin === new URL(request.url).origin;
}
