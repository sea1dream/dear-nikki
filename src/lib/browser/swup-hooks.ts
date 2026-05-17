import { pageview } from "@vercel/analytics";
import { pathsEqual, url } from "@utils/url";
import { BANNER_HEIGHT } from "../../constants/constants";
import { getLenis } from "./lenis";
import { initCustomScrollbar } from "./scrollbar";
import { trackSiteStatsPageView } from "./site-stats";

const bannerEnabled = !!document.getElementById("banner-wrapper");

let lenisResizeTimeout: number | null = null;

/**
 * Debounced Lenis resize function
 */
function debouncedLenisResize() {
    if (lenisResizeTimeout !== null) {
        clearTimeout(lenisResizeTimeout);
    }
    lenisResizeTimeout = window.setTimeout(() => {
        requestAnimationFrame(() => getLenis()?.resize());
        lenisResizeTimeout = null;
    }, 150);
}

/**
 * Setup all Swup page transition hooks
 */
export function setupSwupHooks() {
    let hasHandledInitialPageView = false;

    window.swup.hooks.on("link:click", () => {
        // Remove the delay for the first time page load
        document.documentElement.style.setProperty("--content-delay", "0ms");

        // prevent elements from overlapping the navbar
        if (!bannerEnabled) {
            return;
        }
        const threshold = window.innerHeight * (BANNER_HEIGHT / 100) - 72 - 16;
        const navbar = document.getElementById("navbar-wrapper");
        if (!navbar || !document.body.classList.contains("lg:is-home")) {
            return;
        }
        if (
            document.body.scrollTop >= threshold ||
            document.documentElement.scrollTop >= threshold
        ) {
            navbar.classList.add("navbar-hidden");
        }
    });

    window.swup.hooks.on("content:replace", () => {
        initCustomScrollbar();
        debouncedLenisResize();
    });

    window.swup.hooks.on("visit:start", (visit: { to: { url: string } }) => {
        // change banner height immediately when a link is clicked
        const bodyElement = document.querySelector("body");
        if (bodyElement) {
            if (pathsEqual(visit.to.url, url("/"))) {
                bodyElement.classList.add("lg:is-home");
            } else {
                bodyElement.classList.remove("lg:is-home");
            }
        }

        // increase the page height during page transition to prevent the scrolling animation from jumping
        const heightExtend = document.getElementById("page-height-extend");
        if (heightExtend) {
            heightExtend.classList.remove("hidden");
        }

        // Hide the TOC while scrolling back to top
        const toc = document.getElementById("toc-wrapper");
        if (toc) {
            toc.classList.add("toc-not-ready");
        }
    });

    window.swup.hooks.on("page:view", () => {
        if (!hasHandledInitialPageView) {
            hasHandledInitialPageView = true;
            return;
        }

        pageview({
            path: window.location.pathname,
            route: window.location.pathname,
        });

        void trackSiteStatsPageView();

        // hide the temp high element when the transition is done
        const heightExtend = document.getElementById("page-height-extend");
        if (heightExtend) {
            heightExtend.classList.remove("hidden");
        }
    });

    window.swup.hooks.on("visit:end", (_visit: { to: { url: string } }) => {
        setTimeout(() => {
            const heightExtend = document.getElementById("page-height-extend");
            if (heightExtend) {
                heightExtend.classList.add("hidden");
            }

            // Just make the transition looks better
            const toc = document.getElementById("toc-wrapper");
            if (toc) {
                toc.classList.remove("toc-not-ready");
            }
        }, 200);
    });
}

/**
 * Initialize Swup hooks when available
 */
export function initSwupHooks() {
    if (window?.swup?.hooks) {
        setupSwupHooks();
    } else {
        document.addEventListener("swup:enable", setupSwupHooks);
    }
}
