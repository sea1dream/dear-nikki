/**
 * TableOfContents custom element for tracking and highlighting active headings
 * in a document based on scroll position
 */
class TableOfContents extends HTMLElement {
    tocEl: HTMLElement | null = null;
    visibleClass = "visible";
    observer: IntersectionObserver;
    anchorNavTarget: HTMLElement | null = null;
    headingIdxMap = new Map<string, number>();
    headings: HTMLElement[] = [];
    sections: HTMLElement[] = [];
    tocEntries: HTMLAnchorElement[] = [];
    active: boolean[] = [];
    activeIndicator: HTMLElement | null = null;
    private updatePending = false;

    constructor() {
        super();
        this.observer = new IntersectionObserver(this.handleIntersections, {
            threshold: 0,
        });
    }

    private getHeadingIndexFromEntry(entry: IntersectionObserverEntry) {
        const target = entry.target as HTMLElement;
        const heading = target.firstElementChild as HTMLElement | null;
        const id = heading?.getAttribute("id") ?? null;
        if (!id) return undefined;
        return this.headingIdxMap.get(id);
    }

    handleIntersections = (entries: IntersectionObserverEntry[]) => {
        entries.forEach((entry) => {
            const idx = this.getHeadingIndexFromEntry(entry);
            if (idx !== undefined) {
                this.active[idx] = entry.isIntersecting;
            }

            const target = entry.target as HTMLElement;
            const heading = target.firstElementChild as HTMLElement | null;
            if (entry.isIntersecting && this.anchorNavTarget === heading) {
                this.anchorNavTarget = null;
            }
        });

        if (!this.active.some(Boolean)) {
            this.applyFallbackActiveSection();
        }

        this.update();
    };

    toggleActiveHeading = () => {
        if (!this.tocEntries.length) return;

        let min = this.active.length;
        let max = -1;

        // First pass: find min and max indices
        for (let i = this.active.length - 1; i >= 0; i--) {
            if (this.active[i]) {
                if (i < min) min = i;
                if (i > max) max = i;
            }
        }

        // Batch DOM reads first to prevent layout thrashing
        let parentRect: DOMRect | undefined;
        let scrollOffset: number | undefined;
        let topRect: DOMRect | undefined;
        let bottomRect: DOMRect | undefined;

        if (min <= max && this.tocEl) {
            parentRect = this.tocEl.getBoundingClientRect();
            scrollOffset = this.tocEl.scrollTop;
            topRect = this.tocEntries[min].getBoundingClientRect();
            bottomRect = this.tocEntries[max].getBoundingClientRect();
        }

        // Then batch DOM writes
        for (let i = this.active.length - 1; i >= 0; i--) {
            this.tocEntries[i].classList.toggle(
                this.visibleClass,
                this.active[i],
            );
            if (this.active[i]) {
                this.tocEntries[i].setAttribute("aria-current", "location");
            } else {
                this.tocEntries[i].removeAttribute("aria-current");
            }
        }

        if (
            min > max ||
            !this.tocEl ||
            !parentRect ||
            !topRect ||
            !bottomRect
        ) {
            this.activeIndicator?.setAttribute("style", "opacity: 0");
            return;
        }

        if (scrollOffset === undefined) return;

        const top = topRect.top - parentRect.top + scrollOffset;
        const bottom = bottomRect.bottom - parentRect.top + scrollOffset;

        this.activeIndicator?.setAttribute(
            "style",
            `top: ${top}px; height: ${bottom - top}px`,
        );
    };

    scrollToActiveHeading = () => {
        if (this.anchorNavTarget || !this.tocEl) return;

        const activeEntries = this.tocEl.querySelectorAll<HTMLElement>(
            `.${this.visibleClass}`,
        );
        if (!activeEntries.length) return;

        const topmost = activeEntries[0];
        const bottommost = activeEntries[activeEntries.length - 1];
        const tocHeight = this.tocEl.clientHeight;
        const tocRect = this.tocEl.getBoundingClientRect();
        const scrollOffset = this.tocEl.scrollTop;
        const topmostOffset =
            topmost.getBoundingClientRect().top - tocRect.top + scrollOffset;
        const bottommostOffset =
            bottommost.getBoundingClientRect().top - tocRect.top + scrollOffset;

        let top: number;
        const visibleSpan =
            bottommost.getBoundingClientRect().bottom -
            topmost.getBoundingClientRect().top;

        if (visibleSpan < 0.9 * tocHeight) {
            top = topmostOffset - 32;
        } else {
            top = bottommostOffset - tocHeight * 0.8;
        }

        top = Math.max(0, Math.min(top, this.tocEl.scrollHeight - tocHeight));

        this.tocEl.scrollTo({
            top,
            left: 0,
            behavior: "smooth",
        });
    };

    update = () => {
        if (this.updatePending) return;
        this.updatePending = true;

        requestAnimationFrame(() => {
            this.updatePending = false;
            this.toggleActiveHeading();
            this.scrollToActiveHeading();
        });
    };

    applyFallbackActiveSection = () => {
        if (!this.sections.length) return;

        for (let i = 0; i < this.sections.length; i++) {
            const rect = this.sections[i].getBoundingClientRect();
            const offsetTop = rect.top;
            const offsetBottom = rect.bottom;

            if (
                this.isInRange(offsetTop, 0, window.innerHeight) ||
                this.isInRange(offsetBottom, 0, window.innerHeight) ||
                (offsetTop < 0 && offsetBottom > window.innerHeight)
            ) {
                this.active[i] = true;
            } else if (offsetTop > window.innerHeight) {
                break;
            }
        }
    };

    handleAnchorClick = (event: Event) => {
        const anchor = event
            .composedPath()
            .find((el) => el instanceof HTMLAnchorElement) as
            | HTMLAnchorElement
            | undefined;

        if (!anchor) return;

        const id = decodeURIComponent(anchor.hash?.substring(1));
        const idx = this.headingIdxMap.get(id);

        this.anchorNavTarget = idx !== undefined ? this.headings[idx] : null;
    };

    private isInRange(value: number, min: number, max: number) {
        return min < value && value < max;
    }

    connectedCallback() {
        // Wait for the onload animation to finish so `getBoundingClientRect`
        // returns correct values.
        const animatedElement = document.querySelector(".prose");
        if (animatedElement) {
            animatedElement.addEventListener(
                "animationend",
                () => this.init(),
                {
                    once: true,
                },
            );
        } else {
            // If the animated element isn't found, just initialize immediately.
            this.init();
        }
    }

    init() {
        this.tocEl = this.closest<HTMLElement>("[data-toc-scroll]");

        if (!this.tocEl) return;

        this.addEventListener("click", this.handleAnchorClick, {
            capture: true,
        });

        this.activeIndicator = this.querySelector<HTMLElement>(
            "[data-active-indicator]",
        );

        this.tocEntries = Array.from(
            this.querySelectorAll<HTMLAnchorElement>("a[href^='#']"),
        );

        if (!this.tocEntries.length) return;

        this.sections = new Array(this.tocEntries.length);
        this.headings = new Array(this.tocEntries.length);

        for (let i = 0; i < this.tocEntries.length; i++) {
            const id = decodeURIComponent(
                this.tocEntries[i].hash?.substring(1),
            );
            const heading = document.getElementById(id);
            const section = heading?.parentElement;

            if (
                heading instanceof HTMLElement &&
                section instanceof HTMLElement
            ) {
                this.headings[i] = heading;
                this.sections[i] = section;
                this.headingIdxMap.set(id, i);
            }
        }

        this.active = new Array(this.tocEntries.length).fill(false);

        this.sections.forEach((section) => {
            this.observer.observe(section);
        });

        this.applyFallbackActiveSection();
        this.update();
    }

    disconnectedCallback() {
        this.sections.forEach((section) => {
            this.observer.unobserve(section);
        });
        this.observer.disconnect();
        this.removeEventListener("click", this.handleAnchorClick);
    }
}

/**
 * Initialize the TableOfContents custom element
 * Registers the custom element if not already defined
 */
export function initTableOfContents() {
    if (!customElements.get("table-of-contents")) {
        customElements.define("table-of-contents", TableOfContents);
    }
}
