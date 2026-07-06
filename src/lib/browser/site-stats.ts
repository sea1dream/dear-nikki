import FingerprintJS from "@fingerprintjs/fingerprintjs";

type StatsSnapshot = {
    error: null | string;
    pending: boolean;
    todayVisits: null | number;
    totalVisitors: null | number;
    totalVisits: null | number;
};

export type PostReadStatsSnapshot = {
    readers: number;
    views: number;
};

type StatsListener = (snapshot: StatsSnapshot) => void;

type CounterAction = "get" | "up";

const DEFAULT_SNAPSHOT: StatsSnapshot = {
    todayVisits: null,
    totalVisits: null,
    totalVisitors: null,
    pending: false,
    error: null,
};

declare global {
    interface Window {
        __DEAR_NIKKI_SITE_STATS__?: SiteStatsController;
    }
}

class SiteStatsController {
    private readonly listeners = new Set<StatsListener>();
    private readonly namespace = this.resolveNamespace();
    private readonly timezone = "Asia/Shanghai";

    private inflightPath: null | string = null;
    private knownVisitor = false;
    private pendingPath: null | string = null;
    private snapshot: StatsSnapshot = DEFAULT_SNAPSHOT;
    private trackedPath: null | string = null;
    private visitorIdPromise: null | Promise<string> = null;

    subscribe(listener: StatsListener) {
        this.listeners.add(listener);
        listener(this.snapshot);

        return () => {
            this.listeners.delete(listener);
        };
    }

    async trackCurrentPage() {
        return this.trackPage(
            `${window.location.pathname}${window.location.search}`,
        );
    }

    async trackPage(path: string) {
        const normalizedPath = this.normalizePath(path);

        if (this.inflightPath === normalizedPath) {
            return;
        }

        if (
            this.trackedPath === normalizedPath &&
            this.snapshot.todayVisits !== null &&
            this.snapshot.totalVisits !== null &&
            this.snapshot.totalVisitors !== null
        ) {
            return;
        }

        if (this.inflightPath) {
            this.pendingPath = normalizedPath;
            return;
        }

        this.inflightPath = normalizedPath;
        this.updateSnapshot({
            ...this.snapshot,
            pending: true,
            error: null,
        });

        try {
            const stats = await this.collectStats();
            if (!stats) {
                this.updateSnapshot({
                    ...this.snapshot,
                    pending: false,
                    error: "统计服务暂时不可用",
                });
                return;
            }

            this.trackedPath = normalizedPath;
            this.updateSnapshot({
                ...stats,
                pending: false,
                error: null,
            });
        } finally {
            this.inflightPath = null;

            if (this.pendingPath && this.pendingPath !== this.trackedPath) {
                const nextPath = this.pendingPath;
                this.pendingPath = null;
                void this.trackPage(nextPath);
            } else {
                this.pendingPath = null;
            }
        }
    }

    async trackPostRead(path: string): Promise<null | PostReadStatsSnapshot> {
        const postCounterKey = await this.buildPostCounterKey(path);
        const visitorId = await this.getVisitorId();
        const viewsKey = `${postCounterKey}:views`;
        const readersKey = `${postCounterKey}:readers`;
        const readerKey = `${postCounterKey}:reader:${visitorId}`;

        const [views, existingReaderCount] = await Promise.all([
            this.requestCounter(viewsKey, "up"),
            this.requestCounter(readerKey, "get"),
        ]);

        if (views === null || existingReaderCount === null) {
            return null;
        }

        if (existingReaderCount > 0) {
            const readers = await this.requestCounter(readersKey, "get");
            return readers === null ? null : { views, readers };
        }

        const [registeredReader, readers] = await Promise.all([
            this.requestCounter(readerKey, "up"),
            this.requestCounter(readersKey, "up"),
        ]);

        if (registeredReader === null || readers === null) {
            return null;
        }

        return { views, readers };
    }

    private async collectStats() {
        const dateKey = this.getDateKey();
        const [todayVisits, totalVisits, totalVisitors] = await Promise.all([
            this.requestCounter(`pageviews:${dateKey}`, "up"),
            this.requestCounter("pageviews:total", "up"),
            this.ensureVisitorRegistered(),
        ]);

        if (
            todayVisits === null ||
            totalVisits === null ||
            totalVisitors === null
        ) {
            return null;
        }

        return {
            todayVisits,
            totalVisits,
            totalVisitors,
        };
    }

    private async ensureVisitorRegistered() {
        const totalVisitorsKey = "visitors:total";

        if (this.knownVisitor) {
            return this.requestCounter(totalVisitorsKey, "get");
        }

        const visitorId = await this.getVisitorId();
        const visitorCounterKey = `visitors:device:${visitorId}`;
        const existingVisitorCount = await this.requestCounter(
            visitorCounterKey,
            "get",
        );

        if (existingVisitorCount === null) {
            return null;
        }

        if (existingVisitorCount > 0) {
            this.knownVisitor = true;
            return this.requestCounter(totalVisitorsKey, "get");
        }

        const [registeredVisitor, totalVisitors] = await Promise.all([
            this.requestCounter(visitorCounterKey, "up"),
            this.requestCounter(totalVisitorsKey, "up"),
        ]);

        if (registeredVisitor === null || totalVisitors === null) {
            return null;
        }

        this.knownVisitor = true;
        return totalVisitors;
    }

    private async getVisitorId() {
        if (!this.visitorIdPromise) {
            this.visitorIdPromise = FingerprintJS.load()
                .then((agent) => agent.get())
                .then((result) => result.visitorId);
        }

        return this.visitorIdPromise;
    }

    private getDateKey() {
        return new Intl.DateTimeFormat("en-CA", {
            timeZone: this.timezone,
            year: "numeric",
            month: "2-digit",
            day: "2-digit",
        }).format(new Date());
    }

    private normalizePath(path: string) {
        return path.trim() || "/";
    }

    private normalizePostPath(path: string) {
        const rawPath = path.trim() || window.location.pathname || "/";

        try {
            return new URL(rawPath, window.location.origin).pathname || "/";
        } catch {
            return rawPath.split(/[?#]/)[0] || "/";
        }
    }

    private async buildPostCounterKey(path: string) {
        const normalizedPath = this.normalizePostPath(path);
        const hashedPath = await this.hashCounterKey(normalizedPath);

        return `post-v2:${hashedPath}`;
    }

    private async hashCounterKey(value: string) {
        if (globalThis.crypto?.subtle && globalThis.TextEncoder) {
            const bytes = new TextEncoder().encode(value);
            const digest = await globalThis.crypto.subtle.digest(
                "SHA-256",
                bytes,
            );

            return Array.from(new Uint8Array(digest))
                .map((byte) => byte.toString(16).padStart(2, "0"))
                .join("")
                .slice(0, 32);
        }

        return this.hashCounterKeyFallback(value);
    }

    private hashCounterKeyFallback(value: string) {
        let hash = 0x811c9dc5;

        for (let index = 0; index < value.length; index += 1) {
            hash ^= value.charCodeAt(index);
            hash = Math.imul(hash, 0x01000193);
        }

        return `fnv-${(hash >>> 0).toString(16).padStart(8, "0")}`;
    }

    private notify() {
        for (const listener of this.listeners) {
            listener(this.snapshot);
        }
    }

    private async requestCounter(name: string, action: CounterAction) {
        const endpoint = this.buildCounterEndpoint(name, action);

        try {
            const response = await fetch(endpoint, {
                cache: "no-store",
            });

            if (action === "get" && response.status === 400) {
                return 0;
            }

            if (!response.ok) {
                return null;
            }

            const data = (await response.json()) as { count?: number };
            return typeof data.count === "number" ? data.count : null;
        } catch (error) {
            console.error("Failed to request site stats counter", error);
            return null;
        }
    }

    private buildCounterEndpoint(name: string, action: CounterAction) {
        const encodedNamespace = encodeURIComponent(this.namespace);
        const encodedName = encodeURIComponent(name);

        if (action === "up") {
            return `https://api.counterapi.dev/v1/${encodedNamespace}/${encodedName}/up`;
        }

        return `https://api.counterapi.dev/v1/${encodedNamespace}/${encodedName}/`;
    }

    private resolveNamespace() {
        const baseNamespace = "dear-nikki-sea1dream-stats";
        const hostname = window.location.hostname;
        const isLocalHost =
            hostname === "localhost" ||
            hostname === "127.0.0.1" ||
            hostname === "::1";

        return isLocalHost ? `${baseNamespace}-local` : baseNamespace;
    }

    private updateSnapshot(nextSnapshot: StatsSnapshot) {
        this.snapshot = nextSnapshot;
        this.notify();
    }
}

export function getSiteStatsController() {
    if (!window.__DEAR_NIKKI_SITE_STATS__) {
        window.__DEAR_NIKKI_SITE_STATS__ = new SiteStatsController();
    }

    return window.__DEAR_NIKKI_SITE_STATS__;
}

export async function trackSiteStatsPageView(path?: string) {
    const controller = getSiteStatsController();
    return controller.trackPage(
        path ?? `${window.location.pathname}${window.location.search}`,
    );
}

export async function trackPostReadStats(path?: string) {
    const controller = getSiteStatsController();
    return controller.trackPostRead(path ?? window.location.pathname);
}
