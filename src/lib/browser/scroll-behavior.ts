import {
    BANNER_HEIGHT,
    BANNER_HEIGHT_EXTEND,
    BANNER_HEIGHT_HOME,
    MAIN_PANEL_OVERLAPS_BANNER_HEIGHT,
} from "../../constants/constants";
import { getLenis } from "./lenis";

const bannerEnabled = !!document.getElementById("banner-wrapper");

/**
 * Handle scroll events for the back-to-top button and navbar visibility.
 */
function scrollFunction() {
    const backToTopBtn = document.getElementById("back-to-top-btn");
    const navbar = document.getElementById("navbar-wrapper");

    const bannerHeight = window.innerHeight * (BANNER_HEIGHT / 100);

    if (backToTopBtn) {
        if (
            document.body.scrollTop > bannerHeight ||
            document.documentElement.scrollTop > bannerHeight
        ) {
            backToTopBtn.classList.remove("hide");
        } else {
            backToTopBtn.classList.add("hide");
        }
    }

    if (!bannerEnabled) return;
    if (navbar) {
        const NAVBAR_HEIGHT = 72;
        const MAIN_PANEL_EXCESS_HEIGHT = MAIN_PANEL_OVERLAPS_BANNER_HEIGHT * 16; // The height the main panel overlaps the banner

        let bannerHeight = BANNER_HEIGHT;

        if (
            document.body.classList.contains("lg:is-home") &&
            window.innerWidth >= 1024
        ) {
            bannerHeight = BANNER_HEIGHT_HOME;
        }

        const threshold =
            window.innerHeight * (bannerHeight / 100) -
            NAVBAR_HEIGHT -
            MAIN_PANEL_EXCESS_HEIGHT -
            16;
        if (
            document.body.scrollTop >= threshold ||
            document.documentElement.scrollTop >= threshold
        ) {
            navbar.classList.add("navbar-hidden");
        } else {
            navbar.classList.remove("navbar-hidden");
        }
    }
}

/**
 * Handle window resize for recalculating banner heights
 */
function handleResize() {
    // calculate the --banner-height-extend, which needs to be a multiple of 4 to avoid blurry text
    let offset = Math.floor(window.innerHeight * (BANNER_HEIGHT_EXTEND / 100));
    offset = offset - (offset % 4);
    document.documentElement.style.setProperty(
        "--banner-height-extend",
        `${offset}px`,
    );
    getLenis()?.resize();
}

/**
 * Initialize scroll behavior listeners
 */
export function initScrollBehavior() {
    window.addEventListener("scroll", scrollFunction, { passive: true });
    window.addEventListener("resize", handleResize);

    // Run once on initialization
    scrollFunction();
    handleResize();
}
