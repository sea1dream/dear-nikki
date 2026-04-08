import Lenis from "lenis";
import { siteConfig } from "@/config";

declare global {
    interface Window {
        __DEAR_NIKKI_LENIS__?: InstanceType<typeof Lenis>;
    }
}

let lenis: InstanceType<typeof Lenis> | null = null;
let lenisRafId: number | null = null;

/**
 * Destroy the current Lenis instance and cleanup
 */
export function destroyLenis() {
    if (lenisRafId !== null) {
        cancelAnimationFrame(lenisRafId);
        lenisRafId = null;
    }
    lenis?.destroy();
    lenis = null;
    if (window.__DEAR_NIKKI_LENIS__) {
        delete window.__DEAR_NIKKI_LENIS__;
    }
}

/**
 * Start the Lenis request animation frame loop
 */
function startLenisRaf() {
    const update = (time: number) => {
        if (!lenis) return;
        lenis.raf(time);
        lenisRafId = requestAnimationFrame(update);
    };
    lenisRafId = requestAnimationFrame(update);
}

/**
 * Initialize Lenis smooth scrolling
 */
export function initLenis() {
    destroyLenis();

    if (!siteConfig.scrolling.smooth) return;

    lenis = new Lenis({
        lerp: 0.1,
        smoothWheel: true,
    });

    window.__DEAR_NIKKI_LENIS__ = lenis;

    startLenisRaf();
}

/**
 * Get the current Lenis instance
 */
export function getLenis() {
    return lenis;
}
