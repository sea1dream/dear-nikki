<script lang="ts">
import Icon from "@iconify/svelte";
import type {
    PDFDocumentLoadingTask,
    PDFDocumentProxy,
    PDFPageProxy,
    RefProxy,
    RenderTask,
} from "pdfjs-dist";
import workerUrl from "pdfjs-dist/build/pdf.worker.min.mjs?url";
import { onDestroy, onMount, tick } from "svelte";
import type { ResourceItem, ResourceListResponse } from "@/types/resources";

type PageStatus = "idle" | "rendering" | "rendered" | "error";
type DocumentIndexMode = "outline" | "pages";

interface PageState {
    number: number;
    baseWidth: number;
    baseHeight: number;
    status: PageStatus;
    renderedKey: string;
    error: string;
}

interface ReadingPosition {
    version: 1;
    page: number;
    offset: number;
}

interface PdfOutlineNode {
    title: string;
    bold: boolean;
    italic: boolean;
    dest: string | unknown[] | null;
    items: PdfOutlineNode[];
}

interface OutlineCandidate {
    id: string;
    title: string;
    level: number;
    bold: boolean;
    italic: boolean;
    destination: string | unknown[] | null;
}

interface OutlineEntry extends Omit<OutlineCandidate, "destination"> {
    page: number | null;
}

const MAX_FIT_WIDTH = 1100;
const MIN_FIT_SCALE = 0.1;
const MIN_SCALE = 0.25;
const MAX_SCALE = 3;
const PAGE_RENDER_MARGIN = "1600px 0px";
const PROGRESS_SAVE_DELAY = 350;
const MAX_CANVAS_PIXELS = 18_000_000;
const MAX_OUTPUT_SCALE = 8;
const OUTPUT_QUALITY_DELAY = 180;

let resource: ResourceItem | null = null;
let pdfDocument: PDFDocumentProxy | null = null;
let loadingTask: PDFDocumentLoadingTask | null = null;
let readerShell: HTMLElement;
let viewerStage: HTMLDivElement;
let indexToggleButton: HTMLButtonElement;
let indexSearchInput: HTMLInputElement;
let documentIndexDialog: HTMLElement;
let resizeObserver: ResizeObserver | null = null;
let renderObserver: IntersectionObserver | null = null;
let resizeFrame = 0;
let scrollFrame = 0;
let outputQualityTimer = 0;
let viewRefreshSequence = 0;
let progressSaveTimer = 0;
let resumeNoticeTimer = 0;
let viewRefreshing = false;
let progressReady = false;
let loading = true;
let loadProgress = 0;
let errorMessage = "";
let pageNumber = 1;
let pageCount = 0;
let pageField = "1";
let pages: PageState[] = [];
let viewerWidth = 900;
let zoom = 1;
let actualScale = 1;
let visualViewportScale = 1;
let fitWidth = true;
let rotation = 0;
let readingPercent = 0;
let resumeNotice = "";
let documentIndexOpen = false;
let documentIndexLoading = false;
let documentIndexMode: DocumentIndexMode = "outline";
let documentIndexQuery = "";
let documentIndexError = "";
let outlineEntries: OutlineEntry[] = [];
let pageLabels: string[] = [];
let allPageNumbers: number[] = [];
let filteredOutlineEntries: OutlineEntry[] = [];
let filteredPageNumbers: number[] = [];
let hasOutline = false;
let activeOutlineId = "";
let indexLoadSequence = 0;
let passwordOpen = false;
let passwordIncorrect = false;
let passwordValue = "";
let submitPassword: ((password: string) => void) | null = null;

const pageElements = new Map<number, HTMLElement>();
const canvasElements = new Map<number, HTMLCanvasElement>();
const nearPages = new Set<number>();
const renderTasks = new Map<number, RenderTask>();
const renderVersions = new Map<number, number>();

$: actualScale = pages[0] ? getPageScale(pages[0], viewerWidth) : 1;
$: hasOutline = outlineEntries.some((entry) => entry.page !== null);
$: filteredOutlineEntries = filterOutlineEntries(
    outlineEntries,
    documentIndexQuery,
    pageLabels,
);
$: filteredPageNumbers = filterPageNumbers(
    allPageNumbers,
    documentIndexQuery,
    pageLabels,
);
$: activeOutlineId = findActiveOutlineId(outlineEntries, pageNumber);

function clamp(value: number, minimum: number, maximum: number): number {
    return Math.min(Math.max(value, minimum), maximum);
}

function formatBytes(bytes: number): string {
    if (!Number.isFinite(bytes) || bytes < 1) return "0 B";
    const units = ["B", "KB", "MB", "GB", "TB"];
    const index = Math.min(
        Math.floor(Math.log(bytes) / Math.log(1024)),
        units.length - 1,
    );
    const value = bytes / 1024 ** index;
    return `${value.toFixed(index === 0 || value >= 10 ? 0 : 1)} ${units[index]}`;
}

async function fetchResource(): Promise<ResourceItem> {
    const id = new URLSearchParams(window.location.search).get("id");
    if (!id) throw new Error("缺少资源编号");

    const response = await fetch("/api/resources/");
    if (!response.ok) throw new Error("资源列表暂时无法读取");
    const body = (await response.json()) as ResourceListResponse;
    const item = body.resources.find((candidate) => candidate.id === id);
    if (!item) throw new Error("资源不存在或已被删除");
    return item;
}

function normalizeIndexSearch(value: string): string {
    return value.trim().replace(/\s+/g, " ").toLocaleLowerCase();
}

function pageDisplayLabel(number: number, labels = pageLabels): string {
    const label = labels[number - 1]?.trim();
    return label || String(number);
}

function filterOutlineEntries(
    entries: OutlineEntry[],
    query: string,
    labels: string[],
): OutlineEntry[] {
    const term = normalizeIndexSearch(query);
    if (!term) return entries;
    return entries.filter((entry) => {
        const page = entry.page;
        return (
            normalizeIndexSearch(entry.title).includes(term) ||
            (page !== null &&
                (String(page).includes(term) ||
                    normalizeIndexSearch(
                        pageDisplayLabel(page, labels),
                    ).includes(term)))
        );
    });
}

function filterPageNumbers(
    numbers: number[],
    query: string,
    labels: string[],
): number[] {
    const term = normalizeIndexSearch(query);
    if (!term) return numbers;
    return numbers.filter(
        (number) =>
            String(number).includes(term) ||
            normalizeIndexSearch(pageDisplayLabel(number, labels)).includes(
                term,
            ),
    );
}

function findActiveOutlineId(
    entries: OutlineEntry[],
    currentPage: number,
): string {
    let active: OutlineEntry | null = null;
    for (const entry of entries) {
        if (entry.page === null || entry.page > currentPage) continue;
        if (
            active === null ||
            active.page === null ||
            entry.page > active.page ||
            (entry.page === active.page && entry.level >= active.level)
        ) {
            active = entry;
        }
    }
    return active?.id || "";
}

function flattenOutline(nodes: PdfOutlineNode[]): OutlineCandidate[] {
    const result: OutlineCandidate[] = [];
    const stack = [...nodes].reverse().map((node) => ({ node, level: 0 }));
    let sequence = 0;

    while (stack.length > 0) {
        const current = stack.pop();
        if (!current) break;
        const { node, level } = current;
        const title = node.title?.replace(/\s+/g, " ").trim() || "未命名章节";
        result.push({
            id: `pdf-outline-${sequence++}`,
            title,
            level,
            bold: Boolean(node.bold),
            italic: Boolean(node.italic),
            destination: node.dest,
        });

        const children = Array.isArray(node.items) ? node.items : [];
        for (let index = children.length - 1; index >= 0; --index) {
            stack.push({ node: children[index], level: level + 1 });
        }
    }
    return result;
}

function isPageReference(value: unknown): value is RefProxy {
    if (!value || typeof value !== "object") return false;
    const reference = value as Partial<RefProxy>;
    return Number.isInteger(reference.num) && Number.isInteger(reference.gen);
}

async function resolveOutlinePage(
    document: PDFDocumentProxy,
    destination: string | unknown[] | null,
    namedDestinations: Map<string, Promise<unknown[] | null>>,
    pageReferences: Map<string, Promise<number | null>>,
): Promise<number | null> {
    if (!destination) return null;

    let explicitDestination: unknown[] | null;
    try {
        if (typeof destination === "string") {
            let request = namedDestinations.get(destination);
            if (!request) {
                request = document.getDestination(destination);
                namedDestinations.set(destination, request);
            }
            explicitDestination = await request;
        } else {
            explicitDestination = destination;
        }
    } catch {
        return null;
    }

    if (!Array.isArray(explicitDestination)) return null;
    const reference = explicitDestination[0];
    if (Number.isInteger(reference)) {
        const page = Number(reference) + 1;
        return page >= 1 && page <= document.numPages ? page : null;
    }
    if (!isPageReference(reference)) return null;

    const key = `${reference.num}:${reference.gen}`;
    let request = pageReferences.get(key);
    if (!request) {
        request = document
            .getPageIndex(reference)
            .then((index) => index + 1)
            .catch(() => null);
        pageReferences.set(key, request);
    }
    const page = await request;
    return page !== null && page >= 1 && page <= document.numPages
        ? page
        : null;
}

async function loadDocumentIndex(document: PDFDocumentProxy): Promise<void> {
    const sequence = ++indexLoadSequence;
    documentIndexLoading = true;
    documentIndexError = "";
    outlineEntries = [];
    pageLabels = Array.from({ length: document.numPages }, (_, index) =>
        String(index + 1),
    );
    allPageNumbers = Array.from(
        { length: document.numPages },
        (_, index) => index + 1,
    );

    const [outlineResult, labelsResult] = await Promise.allSettled([
        document.getOutline(),
        document.getPageLabels(),
    ]);
    if (sequence !== indexLoadSequence || document !== pdfDocument) return;

    if (
        labelsResult.status === "fulfilled" &&
        labelsResult.value?.length === document.numPages
    ) {
        pageLabels = labelsResult.value.map(
            (label, index) => label?.trim() || String(index + 1),
        );
    }

    const nodes =
        outlineResult.status === "fulfilled" &&
        Array.isArray(outlineResult.value)
            ? (outlineResult.value as PdfOutlineNode[])
            : [];
    const candidates = flattenOutline(nodes);
    const namedDestinations = new Map<string, Promise<unknown[] | null>>();
    const pageReferences = new Map<string, Promise<number | null>>();
    const resolvedEntries = await Promise.all(
        candidates.map(
            async (candidate): Promise<OutlineEntry> => ({
                id: candidate.id,
                title: candidate.title,
                level: candidate.level,
                bold: candidate.bold,
                italic: candidate.italic,
                page: await resolveOutlinePage(
                    document,
                    candidate.destination,
                    namedDestinations,
                    pageReferences,
                ),
            }),
        ),
    );
    if (sequence !== indexLoadSequence || document !== pdfDocument) return;

    outlineEntries = resolvedEntries;
    documentIndexMode = resolvedEntries.some((entry) => entry.page !== null)
        ? "outline"
        : "pages";
    if (outlineResult.status === "rejected") {
        documentIndexError = "PDF 目录读取失败";
    }
    documentIndexLoading = false;
}

async function openDocumentIndex(): Promise<void> {
    documentIndexOpen = true;
    await tick();
    indexSearchInput?.focus({ preventScroll: true });
    if (documentIndexMode === "outline" && activeOutlineId) {
        documentIndexDialog
            ?.querySelector<HTMLElement>(
                `[data-outline-id="${activeOutlineId}"]`,
            )
            ?.scrollIntoView({ block: "center" });
    }
}

async function closeDocumentIndex(restoreFocus = true): Promise<void> {
    documentIndexOpen = false;
    documentIndexQuery = "";
    await tick();
    if (restoreFocus) {
        indexToggleButton?.focus({ preventScroll: true });
    }
}

function toggleDocumentIndex(): void {
    if (documentIndexOpen) {
        void closeDocumentIndex();
    } else {
        void openDocumentIndex();
    }
}

async function selectDocumentIndexMode(mode: DocumentIndexMode): Promise<void> {
    if (mode !== documentIndexMode) {
        documentIndexMode = mode;
        documentIndexQuery = "";
        await tick();
    }
    indexSearchInput?.focus({ preventScroll: true });
}

function jumpToIndexedPage(number: number): void {
    changePage(number);
    void closeDocumentIndex();
}

function handleDocumentKeydown(event: KeyboardEvent): void {
    if (!documentIndexOpen) return;
    if (event.key === "Escape") {
        event.preventDefault();
        void closeDocumentIndex();
        return;
    }
    if (event.key !== "Tab" || !documentIndexDialog) return;

    const focusable = [
        ...documentIndexDialog.querySelectorAll<HTMLElement>(
            'button:not([disabled]), input:not([disabled]), [href], [tabindex]:not([tabindex="-1"])',
        ),
    ].filter((element) => !element.hasAttribute("inert"));
    if (focusable.length === 0) return;

    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const active = document.activeElement;
    if (
        event.shiftKey &&
        (active === first || !documentIndexDialog.contains(active))
    ) {
        event.preventDefault();
        last.focus();
    } else if (
        !event.shiftKey &&
        (active === last || !documentIndexDialog.contains(active))
    ) {
        event.preventDefault();
        first.focus();
    }
}

function rotatedDimensions(page: PageState): [number, number] {
    return rotation % 180 === 0
        ? [page.baseWidth, page.baseHeight]
        : [page.baseHeight, page.baseWidth];
}

function availablePageWidth(width = viewerWidth): number {
    const gutter = width < 640 ? 8 : 48;
    return Math.min(Math.max(width - gutter, 1), MAX_FIT_WIDTH);
}

function getPageScale(page: PageState, width = viewerWidth): number {
    if (!fitWidth) return zoom;
    const [pageWidth] = rotatedDimensions(page);
    return clamp(
        availablePageWidth(width) / pageWidth,
        MIN_FIT_SCALE,
        MAX_SCALE,
    );
}

function readVisualViewportScale(): number {
    const scale = window.visualViewport?.scale ?? 1;
    return Number.isFinite(scale) && scale > 0 ? scale : 1;
}

function isPageVisibleOnScreen(number: number): boolean {
    const element = pageElements.get(number);
    if (!element || !viewerStage) return number === pageNumber;

    const pageRect = element.getBoundingClientRect();
    const stageRect = viewerStage.getBoundingClientRect();
    const visualViewport = window.visualViewport;
    const viewportLeft = visualViewport?.pageLeft ?? window.scrollX;
    const viewportTop = visualViewport?.pageTop ?? window.scrollY;
    const viewportRight =
        viewportLeft + (visualViewport?.width ?? window.innerWidth);
    const viewportBottom =
        viewportTop + (visualViewport?.height ?? window.innerHeight);
    const pageLeft = pageRect.left + window.scrollX;
    const pageTop = pageRect.top + window.scrollY;
    const pageRight = pageRect.right + window.scrollX;
    const pageBottom = pageRect.bottom + window.scrollY;
    const stageLeft = stageRect.left + window.scrollX;
    const stageTop = stageRect.top + window.scrollY;
    const stageRight = stageRect.right + window.scrollX;
    const stageBottom = stageRect.bottom + window.scrollY;

    return (
        pageRight > Math.max(stageLeft, viewportLeft) &&
        pageLeft < Math.min(stageRight, viewportRight) &&
        pageBottom > Math.max(stageTop, viewportTop) &&
        pageTop < Math.min(stageBottom, viewportBottom)
    );
}

function getOutputScale(page: PageState, number: number): number {
    const [baseWidth, baseHeight] = rotatedDimensions(page);
    const pageScale = getPageScale(page);
    const pagePixels = Math.max(
        baseWidth * pageScale * baseHeight * pageScale,
        1,
    );
    // Native pinch zoom enlarges the existing bitmap, so only boost pages that
    // are actually on screen to keep high-DPI rendering within a sane budget.
    const pinchScale = isPageVisibleOnScreen(number) ? visualViewportScale : 1;
    const requestedScale =
        Math.max(window.devicePixelRatio || 1, 1) * pinchScale;

    return clamp(
        Math.min(requestedScale, Math.sqrt(MAX_CANVAS_PIXELS / pagePixels)),
        0.6,
        MAX_OUTPUT_SCALE,
    );
}

function pageStyle(page: PageState, width: number): string {
    const [baseWidth, baseHeight] = rotatedDimensions(page);
    const scale = getPageScale(page, width);
    return `width:${Math.max(Math.round(baseWidth * scale), 1)}px;height:${Math.max(Math.round(baseHeight * scale), 1)}px`;
}

function renderKey(page: PageState, number: number): string {
    return `${rotation}:${getPageScale(page).toFixed(4)}:${getOutputScale(page, number).toFixed(3)}`;
}

function markPage(
    pageNumberToUpdate: number,
    values: Partial<PageState>,
): void {
    const page = pages[pageNumberToUpdate - 1];
    if (!page) return;
    Object.assign(page, values);
    pages = [...pages];
}

function registerPage(node: HTMLElement, number: number) {
    pageElements.set(number, node);
    renderObserver?.observe(node);

    return {
        destroy() {
            renderObserver?.unobserve(node);
            pageElements.delete(number);
            nearPages.delete(number);
        },
    };
}

function registerCanvas(node: HTMLCanvasElement, number: number) {
    node.width = 1;
    node.height = 1;
    canvasElements.set(number, node);
    return {
        destroy() {
            canvasElements.delete(number);
        },
    };
}

function clearCanvas(number: number): void {
    const canvas = canvasElements.get(number);
    if (!canvas) return;
    canvas.width = 1;
    canvas.height = 1;
}

async function waitForTask(number: number): Promise<void> {
    const task = renderTasks.get(number);
    if (!task) return;
    task.cancel();
    try {
        await task.promise;
    } catch {
        // Rendering cancellation is expected while scrolling or changing scale.
    }
    if (renderTasks.get(number) === task) renderTasks.delete(number);
}

function releasePage(number: number): void {
    const page = pages[number - 1];
    if (!page || page.status === "idle") return;

    renderVersions.set(number, (renderVersions.get(number) ?? 0) + 1);
    markPage(number, { status: "idle", renderedKey: "", error: "" });
    void waitForTask(number).then(() => {
        if (!nearPages.has(number)) clearCanvas(number);
    });
}

function updatePageDimensions(page: PageState, pdfPage: PDFPageProxy): void {
    const viewport = pdfPage.getViewport({ scale: 1, rotation: 0 });
    if (
        Math.abs(page.baseWidth - viewport.width) < 0.5 &&
        Math.abs(page.baseHeight - viewport.height) < 0.5
    ) {
        return;
    }
    page.baseWidth = viewport.width;
    page.baseHeight = viewport.height;
    pages = [...pages];
}

async function renderPage(number: number): Promise<void> {
    const pageState = pages[number - 1];
    const canvas = canvasElements.get(number);
    if (
        !pdfDocument ||
        !pageState ||
        !canvas ||
        !nearPages.has(number) ||
        viewRefreshing
    ) {
        return;
    }

    await waitForTask(number);
    if (!nearPages.has(number) || viewRefreshing) return;

    const pdfPage = await pdfDocument.getPage(number);
    updatePageDimensions(pageState, pdfPage);
    const key = renderKey(pageState, number);
    if (pageState.status === "rendered" && pageState.renderedKey === key) {
        return;
    }

    const version = (renderVersions.get(number) ?? 0) + 1;
    renderVersions.set(number, version);
    markPage(number, {
        status: "rendering",
        renderedKey: key,
        error: "",
    });

    try {
        const viewport = pdfPage.getViewport({
            scale: getPageScale(pageState),
            rotation,
        });
        const pixelScale = getOutputScale(pageState, number);
        const context = canvas.getContext("2d", { alpha: false });
        if (!context) throw new Error("浏览器无法创建 PDF 画布");

        canvas.width = Math.max(Math.floor(viewport.width * pixelScale), 1);
        canvas.height = Math.max(Math.floor(viewport.height * pixelScale), 1);
        canvas.style.width = `${Math.floor(viewport.width)}px`;
        canvas.style.height = `${Math.floor(viewport.height)}px`;

        const task = pdfPage.render({
            canvas: null,
            canvasContext: context,
            viewport,
            transform:
                pixelScale === 1
                    ? undefined
                    : [pixelScale, 0, 0, pixelScale, 0, 0],
            background: "rgb(255, 255, 255)",
        });
        renderTasks.set(number, task);
        await task.promise;

        if (renderVersions.get(number) === version && nearPages.has(number)) {
            markPage(number, { status: "rendered", renderedKey: key });
        }
    } catch (error) {
        if (
            renderVersions.get(number) === version &&
            (!(error instanceof Error) ||
                error.name !== "RenderingCancelledException")
        ) {
            markPage(number, {
                status: "error",
                error:
                    error instanceof Error ? error.message : "PDF 页面渲染失败",
            });
        }
    } finally {
        const task = renderTasks.get(number);
        if (task && renderVersions.get(number) === version) {
            renderTasks.delete(number);
        }
    }
}

function setupRenderObserver(): void {
    renderObserver?.disconnect();
    if (!viewerStage) return;

    renderObserver = new IntersectionObserver(
        (entries) => {
            for (const entry of entries) {
                const number = Number(
                    (entry.target as HTMLElement).dataset.pdfPage,
                );
                if (!number) continue;
                if (entry.isIntersecting) {
                    nearPages.add(number);
                    void renderPage(number);
                } else {
                    nearPages.delete(number);
                    releasePage(number);
                }
            }
        },
        { root: viewerStage, rootMargin: PAGE_RENDER_MARGIN },
    );

    pageElements.forEach((element) => {
        renderObserver?.observe(element);
    });
}

function findCurrentPage(): number {
    if (!viewerStage || pageElements.size === 0) return pageNumber;
    const stageRect = viewerStage.getBoundingClientRect();
    const readingLine =
        stageRect.top + Math.min(96, viewerStage.clientHeight * 0.18);
    let low = 1;
    let high = pageCount;

    while (low <= high) {
        const middle = Math.floor((low + high) / 2);
        const element = pageElements.get(middle);
        if (!element) break;
        const rect = element.getBoundingClientRect();
        if (readingLine < rect.top) {
            high = middle - 1;
        } else if (readingLine >= rect.bottom) {
            low = middle + 1;
        } else {
            return middle;
        }
    }

    return clamp(low, 1, pageCount);
}

function captureReadingPosition(number = pageNumber): ReadingPosition {
    const element = pageElements.get(number);
    if (!viewerStage || !element) {
        return { version: 1, page: number, offset: 0 };
    }
    const stageRect = viewerStage.getBoundingClientRect();
    const pageRect = element.getBoundingClientRect();
    return {
        version: 1,
        page: number,
        offset: clamp(
            (stageRect.top - pageRect.top) / Math.max(pageRect.height, 1),
            0,
            0.999,
        ),
    };
}

function progressStorageKey(): string | null {
    const fingerprint = pdfDocument?.fingerprints[0];
    if (fingerprint) return `pdf-reading-progress:v2:${fingerprint}`;
    return resource ? `pdf-reading-progress:${resource.id}` : null;
}

function legacyProgressStorageKey(): string | null {
    return resource ? `pdf-reading-progress:${resource.id}` : null;
}

function saveReadingPosition(): void {
    const key = progressStorageKey();
    if (!progressReady || !key || !pageCount) return;
    try {
        localStorage.setItem(
            key,
            JSON.stringify(captureReadingPosition(findCurrentPage())),
        );
    } catch {
        // Reading still works when browser storage is unavailable.
    }
}

function scheduleProgressSave(): void {
    window.clearTimeout(progressSaveTimer);
    progressSaveTimer = window.setTimeout(
        saveReadingPosition,
        PROGRESS_SAVE_DELAY,
    );
}

function flushProgressSave(): void {
    window.clearTimeout(progressSaveTimer);
    progressSaveTimer = 0;
    saveReadingPosition();
}

function readStoredPosition(): ReadingPosition | null {
    const keys = new Set(
        [progressStorageKey(), legacyProgressStorageKey()].filter(
            (key): key is string => Boolean(key),
        ),
    );

    for (const key of keys) {
        try {
            const parsed = JSON.parse(
                localStorage.getItem(key) ?? "null",
            ) as Partial<ReadingPosition> | null;
            const page = parsed?.page;
            const offset = parsed?.offset;
            if (
                parsed?.version !== 1 ||
                typeof page !== "number" ||
                !Number.isFinite(page) ||
                typeof offset !== "number" ||
                !Number.isFinite(offset)
            ) {
                continue;
            }
            return {
                version: 1,
                page: clamp(Math.round(page), 1, pageCount),
                offset: clamp(offset, 0, 0.999),
            };
        } catch {
            // Ignore malformed or unavailable browser storage and try fallback keys.
        }
    }

    return null;
}

function handleVisibilityChange(): void {
    if (document.visibilityState === "hidden") flushProgressSave();
}

function handlePageHide(): void {
    flushProgressSave();
}

function scrollToPosition(position: ReadingPosition, smooth = false): void {
    const element = pageElements.get(position.page);
    if (!viewerStage || !element) return;
    const stageRect = viewerStage.getBoundingClientRect();
    const pageRect = element.getBoundingClientRect();
    const top =
        viewerStage.scrollTop +
        pageRect.top -
        stageRect.top +
        position.offset * pageRect.height;
    const reduceMotion = window.matchMedia(
        "(prefers-reduced-motion: reduce)",
    ).matches;
    viewerStage.scrollTo({
        top,
        behavior: smooth && !reduceMotion ? "smooth" : "auto",
    });
    pageNumber = position.page;
    pageField = String(position.page);
}

function syncReadingProgress(): void {
    if (!viewerStage || !pageCount) return;
    const current = findCurrentPage();
    pageNumber = current;
    if (
        !(document.activeElement instanceof HTMLInputElement) ||
        document.activeElement.name !== "pdf-page"
    ) {
        pageField = String(current);
    }
    const scrollable = viewerStage.scrollHeight - viewerStage.clientHeight;
    readingPercent =
        scrollable > 0
            ? Math.round((viewerStage.scrollTop / scrollable) * 100)
            : 0;
    if (progressReady) scheduleProgressSave();
}

function handleViewerScroll(): void {
    if (scrollFrame) return;
    scrollFrame = window.requestAnimationFrame(() => {
        scrollFrame = 0;
        syncReadingProgress();
        if (visualViewportScale > 1.01) scheduleOutputQualityRefresh();
    });
}

function refreshOutputQuality(): void {
    for (const number of nearPages) {
        const page = pages[number - 1];
        if (page && page.renderedKey !== renderKey(page, number)) {
            void renderPage(number);
        }
    }
}

function scheduleOutputQualityRefresh(): void {
    window.clearTimeout(outputQualityTimer);
    outputQualityTimer = window.setTimeout(
        refreshOutputQuality,
        OUTPUT_QUALITY_DELAY,
    );
}

function handleVisualViewportChange(): void {
    visualViewportScale = readVisualViewportScale();
    scheduleOutputQualityRefresh();
}

async function refreshRenderedPages(
    anchor: ReadingPosition = captureReadingPosition(),
): Promise<void> {
    const sequence = ++viewRefreshSequence;
    viewRefreshing = true;
    renderVersions.forEach((version, number) => {
        renderVersions.set(number, version + 1);
    });

    await Promise.all([...renderTasks.keys()].map(waitForTask));
    if (sequence !== viewRefreshSequence) return;

    for (const page of pages) {
        page.status = "idle";
        page.renderedKey = "";
        page.error = "";
        clearCanvas(page.number);
    }
    pages = [...pages];
    await tick();
    scrollToPosition(anchor);
    viewRefreshing = false;
    nearPages.forEach((number) => void renderPage(number));
}

function setupResizeObserver(): void {
    resizeObserver?.disconnect();
    if (!viewerStage) return;

    resizeObserver = new ResizeObserver(() => {
        const nextWidth = Math.round(viewerStage.clientWidth);
        if (!nextWidth || nextWidth === viewerWidth) return;
        const anchor = captureReadingPosition();
        window.cancelAnimationFrame(resizeFrame);
        resizeFrame = window.requestAnimationFrame(() => {
            viewerWidth = nextWidth;
            if (fitWidth) void refreshRenderedPages(anchor);
        });
    });
    resizeObserver.observe(viewerStage);
}

async function openPdf(): Promise<void> {
    progressReady = false;
    resource = await fetchResource();
    const pdfjs = await import("pdfjs-dist");
    pdfjs.GlobalWorkerOptions.workerSrc = workerUrl;

    loadingTask = pdfjs.getDocument({
        url: resource.url,
        cMapUrl: "/pdfjs/cmaps/",
        cMapPacked: true,
        standardFontDataUrl: "/pdfjs/standard_fonts/",
        wasmUrl: "/pdfjs/wasm/",
        iccUrl: "/pdfjs/iccs/",
        isEvalSupported: false,
    });
    loadingTask.onProgress = ({ loaded, total }) => {
        if (total > 0) loadProgress = Math.round((loaded / total) * 100);
    };
    loadingTask.onPassword = (callback, reason) => {
        submitPassword = callback;
        passwordIncorrect = reason === 2;
        passwordOpen = true;
        loading = false;
    };

    const document = await loadingTask.promise;
    pdfDocument = document;
    pageCount = document.numPages;
    void loadDocumentIndex(document);
    const firstPage = await document.getPage(1);
    const firstViewport = firstPage.getViewport({ scale: 1, rotation: 0 });
    pages = Array.from({ length: pageCount }, (_, index) => ({
        number: index + 1,
        baseWidth: firstViewport.width,
        baseHeight: firstViewport.height,
        status: "idle",
        renderedKey: "",
        error: "",
    }));
    pageNumber = 1;
    pageField = "1";
    passwordOpen = false;
    loading = false;

    await tick();
    viewerWidth = Math.round(viewerStage.clientWidth) || viewerWidth;
    pages = [...pages];
    await tick();

    const storedPosition = readStoredPosition();
    if (storedPosition) {
        scrollToPosition(storedPosition);
        if (storedPosition.page > 1 || storedPosition.offset > 0.02) {
            resumeNotice = `已继续上次阅读 · 第 ${storedPosition.page} 页`;
            resumeNoticeTimer = window.setTimeout(() => {
                resumeNotice = "";
            }, 2800);
        }
    }
    await new Promise<void>((resolve) => {
        window.requestAnimationFrame(() => resolve());
    });
    setupRenderObserver();
    setupResizeObserver();
    progressReady = true;
    syncReadingProgress();
}

onMount(() => {
    visualViewportScale = readVisualViewportScale();
    window.visualViewport?.addEventListener(
        "resize",
        handleVisualViewportChange,
    );
    window.visualViewport?.addEventListener(
        "scroll",
        handleVisualViewportChange,
    );
    document.addEventListener("visibilitychange", handleVisibilityChange);
    document.addEventListener("keydown", handleDocumentKeydown);
    window.addEventListener("pagehide", handlePageHide);
    openPdf().catch((error) => {
        errorMessage = error instanceof Error ? error.message : "PDF 加载失败";
        loading = false;
    });
});

onDestroy(() => {
    if (typeof window === "undefined") return;
    flushProgressSave();
    window.cancelAnimationFrame(resizeFrame);
    window.cancelAnimationFrame(scrollFrame);
    window.clearTimeout(outputQualityTimer);
    window.clearTimeout(progressSaveTimer);
    window.clearTimeout(resumeNoticeTimer);
    resizeObserver?.disconnect();
    renderObserver?.disconnect();
    window.visualViewport?.removeEventListener(
        "resize",
        handleVisualViewportChange,
    );
    window.visualViewport?.removeEventListener(
        "scroll",
        handleVisualViewportChange,
    );
    document.removeEventListener("visibilitychange", handleVisibilityChange);
    document.removeEventListener("keydown", handleDocumentKeydown);
    window.removeEventListener("pagehide", handlePageHide);
    ++indexLoadSequence;
    renderTasks.forEach((task) => {
        task.cancel();
    });
    if (loadingTask) {
        void loadingTask.destroy();
    } else if (pdfDocument) {
        void pdfDocument.destroy();
    }
});

function changePage(nextPage: number): void {
    if (!Number.isFinite(nextPage) || !pageCount) {
        pageField = String(pageNumber);
        return;
    }
    const boundedPage = clamp(Math.round(nextPage), 1, pageCount);
    const nearby = Math.abs(boundedPage - pageNumber) <= 3;
    scrollToPosition({ version: 1, page: boundedPage, offset: 0 }, nearby);
    if (!nearby) {
        window.requestAnimationFrame(syncReadingProgress);
    }
}

function applyPageField(): void {
    changePage(Number(pageField));
}

function adjustZoom(delta: number): void {
    const anchor = captureReadingPosition();
    zoom = clamp((fitWidth ? actualScale : zoom) + delta, MIN_SCALE, MAX_SCALE);
    fitWidth = false;
    void refreshRenderedPages(anchor);
}

function useFitWidth(): void {
    if (fitWidth) return;
    const anchor = captureReadingPosition();
    fitWidth = true;
    void refreshRenderedPages(anchor);
}

function rotatePages(): void {
    const anchor = captureReadingPosition();
    rotation = (rotation + 90) % 360;
    void refreshRenderedPages(anchor);
}

async function toggleFullscreen(): Promise<void> {
    if (!readerShell) return;
    if (document.fullscreenElement) {
        await document.exitFullscreen();
    } else {
        await readerShell.requestFullscreen();
    }
}

function unlockPdf(): void {
    if (!passwordValue || !submitPassword) return;
    const callback = submitPassword;
    const password = passwordValue;
    passwordValue = "";
    passwordOpen = false;
    passwordIncorrect = false;
    loading = true;
    callback(password);
}
</script>

<section
    bind:this={readerShell}
    data-no-swup
    class="pdf-reader-shell relative overflow-hidden rounded-lg"
>
    <div
        class="card-base flex h-full flex-col overflow-hidden rounded-lg"
        inert={documentIndexOpen}
        aria-hidden={documentIndexOpen}
    >
        <header class="flex min-h-14 items-center gap-2.5 border-b border-black/5 px-2.5 py-2 dark:border-white/10 sm:min-h-16 sm:gap-3 sm:px-5 sm:py-3">
            <a
                href="/resources/"
                class="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-[var(--btn-regular-bg)] text-75 no-underline transition hover:text-[var(--primary)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)] sm:h-10 sm:w-10"
                aria-label="返回资源列表"
                title="返回资源列表"
            >
                <Icon icon="material-symbols:arrow-back-rounded" width="22" />
            </a>
            <div class="min-w-0 flex-1">
                <p class="truncate text-sm font-bold text-90 sm:text-base md:text-lg" title={resource?.title || "PDF 预览"}>
                    {resource?.title || "PDF 预览"}
                </p>
                {#if resource}
                    <p class="mt-0.5 truncate text-xs text-50">
                        {[resource.author, formatBytes(resource.size)].filter(Boolean).join(" · ")}
                    </p>
                {/if}
            </div>
            {#if resource}
                <a
                    href={resource.downloadUrl}
                    class="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-[var(--primary)] text-white no-underline transition hover:brightness-105 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)] sm:h-10 sm:w-10"
                    aria-label="下载 PDF"
                    title="下载 PDF"
                >
                    <Icon icon="material-symbols:download-rounded" width="21" />
                </a>
            {/if}
        </header>

        {#if loading}
            <div class="flex min-h-[38rem] flex-col items-center justify-center px-5 text-center" aria-live="polite">
                <Icon icon="material-symbols:progress-activity" width="32" class="animate-spin text-[var(--primary)]" />
                <p class="mt-4 text-sm font-medium text-75">正在打开 PDF</p>
                {#if loadProgress > 0 && loadProgress < 100}
                    <div class="mt-4 h-1.5 w-full max-w-52 overflow-hidden rounded-full bg-[var(--btn-regular-bg)]">
                        <div
                            class="h-full rounded-full bg-[var(--primary)] transition-[width]"
                            style={`width: ${loadProgress}%`}
                        ></div>
                    </div>
                    <p class="mt-2 text-xs text-30">{loadProgress}%</p>
                {/if}
            </div>
        {:else if passwordOpen}
            <div class="flex min-h-[38rem] items-center justify-center px-5">
                <form class="w-full max-w-sm text-center" on:submit|preventDefault={unlockPdf}>
                    <Icon icon="material-symbols:lock-rounded" width="34" class="mx-auto text-[var(--primary)]" />
                    <h2 class="mt-4 text-lg font-bold text-90">此 PDF 需要密码</h2>
                    {#if passwordIncorrect}
                        <p class="mt-2 text-sm text-red-500">密码不正确，请重试</p>
                    {/if}
                    <label class="mt-5 block">
                        <span class="sr-only">PDF 密码</span>
                        <input
                            bind:value={passwordValue}
                            type="password"
                            name="pdf-password"
                            autocomplete="current-password"
                            class="h-11 w-full rounded-lg border border-black/10 bg-[var(--btn-regular-bg)] px-3 text-center text-sm text-90 outline-none focus-visible:border-[var(--primary)] focus-visible:ring-2 focus-visible:ring-[var(--primary)]/20 dark:border-white/10"
                        />
                    </label>
                    <button
                        type="submit"
                        class="mt-3 h-10 w-full rounded-lg bg-[var(--primary)] text-sm font-semibold text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)]"
                    >
                        解锁
                    </button>
                </form>
            </div>
        {:else if errorMessage}
            <div class="flex min-h-[38rem] flex-col items-center justify-center px-5 text-center">
                <Icon icon="material-symbols:error-outline-rounded" width="34" class="text-red-500" />
                <h2 class="mt-4 text-lg font-bold text-90">无法打开 PDF</h2>
                <p class="mt-2 max-w-md text-sm leading-6 text-50">{errorMessage}</p>
                <div class="mt-5 flex gap-2">
                    <a
                        href="/resources/"
                        class="inline-flex h-10 items-center rounded-lg bg-[var(--btn-regular-bg)] px-4 text-sm font-semibold text-75 no-underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)]"
                    >
                        返回列表
                    </a>
                    <button
                        type="button"
                        class="inline-flex h-10 items-center gap-2 rounded-lg bg-[var(--primary)] px-4 text-sm font-semibold text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)]"
                        on:click={() => window.location.reload()}
                    >
                        <Icon icon="material-symbols:refresh-rounded" width="18" />
                        重试
                    </button>
                </div>
            </div>
        {:else}
            <div class="flex flex-nowrap items-center justify-between gap-1 overflow-hidden border-b border-black/5 bg-[var(--btn-regular-bg)]/45 px-1 py-1.5 dark:border-white/10 sm:px-4 sm:py-2">
                <div class="flex h-8 shrink-0 items-center gap-0 sm:h-9 sm:gap-1">
                    <button
                        bind:this={indexToggleButton}
                        type="button"
                        class={`flex h-8 w-8 items-center justify-center rounded-lg transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)] sm:h-9 sm:w-9 ${documentIndexOpen ? "bg-[var(--primary)] text-white" : "text-75 hover:bg-[var(--btn-regular-bg)]"}`}
                        on:click={toggleDocumentIndex}
                        aria-label={documentIndexOpen ? "关闭文档目录" : "打开文档目录"}
                        aria-controls="pdf-document-index"
                        aria-expanded={documentIndexOpen}
                        title="文档目录"
                    >
                        <Icon icon="material-symbols:toc-rounded" width="21" />
                    </button>
                    <button
                        type="button"
                        class="flex h-8 w-8 items-center justify-center rounded-lg text-75 transition hover:bg-[var(--btn-regular-bg)] disabled:opacity-35 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)] sm:h-9 sm:w-9"
                        disabled={pageNumber <= 1}
                        on:click={() => changePage(pageNumber - 1)}
                        aria-label="上一页"
                        title="上一页"
                    >
                        <Icon icon="material-symbols:chevron-left-rounded" width="22" />
                    </button>
                    <form class="flex items-center gap-1 text-xs text-50 sm:gap-1.5" on:submit|preventDefault={applyPageField}>
                        <input
                            bind:value={pageField}
                            type="number"
                            name="pdf-page"
                            min="1"
                            max={pageCount}
                            class="h-8 w-10 rounded-md border border-black/10 bg-[var(--card-bg)] px-1 text-center text-sm font-semibold text-90 outline-none focus-visible:border-[var(--primary)] focus-visible:ring-2 focus-visible:ring-[var(--primary)]/20 dark:border-white/10 sm:w-14"
                            aria-label="页码"
                            on:change={applyPageField}
                        />
                        <span>/ {pageCount}</span>
                    </form>
                    <button
                        type="button"
                        class="flex h-8 w-8 items-center justify-center rounded-lg text-75 transition hover:bg-[var(--btn-regular-bg)] disabled:opacity-35 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)] sm:h-9 sm:w-9"
                        disabled={pageNumber >= pageCount}
                        on:click={() => changePage(pageNumber + 1)}
                        aria-label="下一页"
                        title="下一页"
                    >
                        <Icon icon="material-symbols:chevron-right-rounded" width="22" />
                    </button>
                </div>

                <span class="hidden text-xs font-semibold tabular-nums text-50 sm:block">
                    {readingPercent}%
                </span>

                <div class="flex h-8 shrink-0 items-center gap-0 sm:h-9 sm:gap-1">
                    <button
                        type="button"
                        class="hidden h-8 w-8 items-center justify-center rounded-lg text-75 transition hover:bg-[var(--btn-regular-bg)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)] min-[350px]:flex sm:h-9 sm:w-9"
                        on:click={() => adjustZoom(-0.15)}
                        aria-label="缩小"
                        title="缩小"
                    >
                        <Icon icon="material-symbols:zoom-out-rounded" width="20" />
                    </button>
                    <span class="hidden w-12 text-center text-xs font-semibold tabular-nums text-50 sm:block">
                        {Math.round(actualScale * 100)}%
                    </span>
                    <button
                        type="button"
                        class="flex h-8 w-8 items-center justify-center rounded-lg text-75 transition hover:bg-[var(--btn-regular-bg)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)] sm:h-9 sm:w-9"
                        on:click={() => adjustZoom(0.15)}
                        aria-label="放大"
                        title="放大"
                    >
                        <Icon icon="material-symbols:zoom-in-rounded" width="20" />
                    </button>
                    <button
                        type="button"
                        class={`flex h-8 w-8 items-center justify-center rounded-lg transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)] sm:h-9 sm:w-9 ${fitWidth ? "bg-[var(--primary)] text-white" : "text-75 hover:bg-[var(--btn-regular-bg)]"}`}
                        on:click={useFitWidth}
                        aria-label="适合宽度"
                        title="适合宽度"
                    >
                        <Icon icon="material-symbols:fit-width-rounded" width="20" />
                    </button>
                    <button
                        type="button"
                        class="flex h-8 w-8 items-center justify-center rounded-lg text-75 transition hover:bg-[var(--btn-regular-bg)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)] sm:h-9 sm:w-9"
                        on:click={rotatePages}
                        aria-label="顺时针旋转"
                        title="顺时针旋转"
                    >
                        <Icon icon="material-symbols:rotate-right-rounded" width="20" />
                    </button>
                    <button
                        type="button"
                        class="flex h-8 w-8 items-center justify-center rounded-lg text-75 transition hover:bg-[var(--btn-regular-bg)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)] sm:h-9 sm:w-9"
                        on:click={toggleFullscreen}
                        aria-label="全屏阅读"
                        title="全屏阅读"
                    >
                        <Icon icon="material-symbols:fullscreen-rounded" width="22" />
                    </button>
                </div>
            </div>
            <div class="h-1 shrink-0 bg-[var(--btn-regular-bg)]" aria-hidden="true">
                <div
                    class="h-full bg-[var(--primary)] transition-[width] duration-150"
                    style={`width:${readingPercent}%`}
                ></div>
            </div>

            <div
                bind:this={viewerStage}
                class="pdf-viewer-stage relative h-[calc(100dvh-6.5rem)] min-h-[28rem] overflow-auto bg-[#d9dde3] overscroll-contain dark:bg-[#22262c] md:h-[82dvh] md:min-h-[36rem] md:max-h-[72rem]"
                data-lenis-prevent
                role="region"
                aria-label="PDF 连续阅读区"
                on:scroll={handleViewerScroll}
            >
                <div
                    class="relative flex w-max min-w-full flex-col items-center gap-4 px-1 py-4 md:gap-5 md:px-6 md:py-5"
                    role="document"
                    aria-label={resource?.title || "PDF 文档"}
                >
                    {#each pages as page (page.number)}
                        <article
                            use:registerPage={page.number}
                            data-pdf-page={page.number}
                            class="relative shrink-0 overflow-hidden bg-white shadow-[0_5px_22px_rgba(0,0,0,0.22)]"
                            style={pageStyle(page, viewerWidth)}
                            aria-label={`第 ${page.number} 页`}
                        >
                            <canvas
                                use:registerCanvas={page.number}
                                class="block h-full w-full bg-white"
                                aria-label={`PDF 第 ${page.number} 页`}
                            ></canvas>
                            {#if page.status === "idle" || page.status === "rendering"}
                                <div class="pointer-events-none absolute inset-0 flex items-center justify-center bg-white text-neutral-400">
                                    {#if page.status === "rendering"}
                                        <Icon icon="material-symbols:progress-activity" width="24" class="animate-spin" />
                                    {:else}
                                        <span class="text-sm font-medium tabular-nums">{page.number}</span>
                                    {/if}
                                </div>
                            {:else if page.status === "error"}
                                <div class="absolute inset-0 flex flex-col items-center justify-center bg-white px-4 text-center text-neutral-500">
                                    <Icon icon="material-symbols:error-outline-rounded" width="28" />
                                    <span class="mt-2 text-sm">第 {page.number} 页加载失败</span>
                                    <button
                                        type="button"
                                        class="mt-3 h-9 rounded-lg bg-neutral-100 px-3 text-xs font-semibold text-neutral-700 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)]"
                                        on:click={() => {
                                            markPage(page.number, { status: "idle", error: "" });
                                            void renderPage(page.number);
                                        }}
                                    >
                                        重试
                                    </button>
                                </div>
                            {/if}
                        </article>
                    {/each}
                </div>
            </div>
        {/if}
    </div>

    <button
        type="button"
        class={`absolute inset-0 z-30 bg-black/40 transition-opacity duration-200 ${documentIndexOpen ? "pointer-events-auto opacity-100" : "pointer-events-none opacity-0"}`}
        aria-label="关闭文档目录"
        aria-hidden={!documentIndexOpen}
        tabindex="-1"
        on:click={() => void closeDocumentIndex()}
    ></button>

    <div
        bind:this={documentIndexDialog}
        id="pdf-document-index"
        class={`absolute inset-y-0 left-0 z-40 flex w-[calc(100%-2rem)] max-w-[22rem] flex-col border-r border-black/10 bg-[var(--card-bg)] shadow-2xl transition-transform duration-200 dark:border-white/10 ${documentIndexOpen ? "translate-x-0" : "-translate-x-full"}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby="pdf-document-index-title"
        aria-hidden={!documentIndexOpen}
        inert={!documentIndexOpen}
    >
        <div class="flex min-h-16 shrink-0 items-center gap-3 border-b border-black/5 px-4 dark:border-white/10">
            <div class="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-[var(--btn-regular-bg)] text-[var(--primary)]">
                <Icon icon="material-symbols:toc-rounded" width="21" />
            </div>
            <div class="min-w-0 flex-1">
                <h2 id="pdf-document-index-title" class="text-base font-bold text-90">文档目录</h2>
                <p class="truncate text-xs text-50" title={resource?.title || "PDF 文档"}>
                    {resource?.title || "PDF 文档"}
                </p>
            </div>
            <button
                type="button"
                class="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-75 transition hover:bg-[var(--btn-regular-bg)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)]"
                on:click={() => void closeDocumentIndex()}
                aria-label="关闭文档目录"
                title="关闭"
            >
                <Icon icon="material-symbols:close-rounded" width="21" />
            </button>
        </div>

        <div class="shrink-0 border-b border-black/5 px-3 py-3 dark:border-white/10">
            {#if documentIndexLoading || hasOutline}
                <div class="mb-3 grid grid-cols-2 rounded-lg bg-[var(--btn-regular-bg)] p-1" role="tablist" aria-label="目录视图">
                    <button
                        type="button"
                        role="tab"
                        aria-selected={documentIndexMode === "outline"}
                        aria-controls="pdf-document-index-panel"
                        tabindex={documentIndexMode === "outline" ? 0 : -1}
                        class={`h-8 rounded-md text-xs font-semibold transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--primary)] ${documentIndexMode === "outline" ? "bg-[var(--card-bg)] text-[var(--primary)] shadow-sm" : "text-50 hover:text-75"}`}
                        on:click={() => void selectDocumentIndexMode("outline")}
                    >
                        目录
                    </button>
                    <button
                        type="button"
                        role="tab"
                        aria-selected={documentIndexMode === "pages"}
                        aria-controls="pdf-document-index-panel"
                        tabindex={documentIndexMode === "pages" ? 0 : -1}
                        class={`h-8 rounded-md text-xs font-semibold transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--primary)] ${documentIndexMode === "pages" ? "bg-[var(--card-bg)] text-[var(--primary)] shadow-sm" : "text-50 hover:text-75"}`}
                        on:click={() => void selectDocumentIndexMode("pages")}
                    >
                        页码
                    </button>
                </div>
            {/if}

            <label class="relative block">
                <span class="sr-only">
                    {documentIndexMode === "outline" ? "搜索目录" : "搜索页码"}
                </span>
                <Icon
                    icon="material-symbols:search-rounded"
                    width="18"
                    class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-30"
                />
                <input
                    bind:this={indexSearchInput}
                    bind:value={documentIndexQuery}
                    type="search"
                    name="pdf-index-search"
                    autocomplete="off"
                    placeholder={documentIndexMode === "outline" ? "搜索章节或页码" : "搜索页码"}
                    class="h-10 w-full rounded-lg border border-black/10 bg-[var(--btn-regular-bg)] pl-9 pr-3 text-sm text-90 outline-none placeholder:text-30 focus-visible:border-[var(--primary)] focus-visible:ring-2 focus-visible:ring-[var(--primary)]/20 dark:border-white/10"
                />
            </label>
        </div>

        <div
            id="pdf-document-index-panel"
            class="min-h-0 flex-1 overflow-y-auto overscroll-contain px-2 py-2"
            data-lenis-prevent
            role="tabpanel"
        >
            {#if documentIndexOpen}
            {#if documentIndexMode === "outline"}
                {#if documentIndexLoading}
                    <div class="flex h-32 items-center justify-center gap-2 text-sm text-50" aria-live="polite">
                        <Icon icon="material-symbols:progress-activity" width="20" class="animate-spin text-[var(--primary)]" />
                        <span>正在读取目录</span>
                    </div>
                {:else if filteredOutlineEntries.length > 0}
                    <nav aria-label="PDF 书签目录" class="space-y-0.5">
                        {#each filteredOutlineEntries as entry (entry.id)}
                            <button
                                type="button"
                                class={`flex min-h-10 w-full items-center gap-2 rounded-md pr-2 text-left text-sm transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--primary)] ${entry.id === activeOutlineId ? "bg-[var(--btn-regular-bg)] text-[var(--primary)]" : entry.page === null ? "cursor-default text-40" : "text-75 hover:bg-[var(--btn-regular-bg)]"}`}
                                class:font-bold={entry.bold}
                                class:italic={entry.italic}
                                data-outline-id={entry.id}
                                style={`padding-left: ${0.75 + Math.min(entry.level, 6) * 0.85}rem`}
                                disabled={entry.page === null}
                                aria-current={entry.id === activeOutlineId ? "location" : undefined}
                                aria-label={entry.page === null ? entry.title : `${entry.title}，第 ${entry.page} 页`}
                                title={entry.page === null ? entry.title : `${entry.title} · 第 ${entry.page} 页`}
                                on:click={() => entry.page !== null && jumpToIndexedPage(entry.page)}
                            >
                                <span class="min-w-0 flex-1 truncate">{entry.title}</span>
                                {#if entry.page !== null}
                                    <span class="max-w-16 shrink-0 truncate text-[0.6875rem] font-semibold tabular-nums text-30">
                                        {pageDisplayLabel(entry.page)}
                                    </span>
                                {/if}
                            </button>
                        {/each}
                    </nav>
                {:else}
                    <div class="flex h-32 flex-col items-center justify-center px-4 text-center text-50">
                        <Icon icon="material-symbols:search-off-rounded" width="26" />
                        <p class="mt-2 text-sm">没有匹配的章节</p>
                    </div>
                {/if}
            {:else}
                {#if documentIndexError}
                    <p class="mb-2 rounded-md bg-red-500/10 px-3 py-2 text-xs text-red-500" role="status">
                        {documentIndexError}
                    </p>
                {:else if !documentIndexLoading && !hasOutline}
                    <p class="mb-2 px-2 py-1 text-xs text-40">未检测到书签目录</p>
                {/if}

                {#if filteredPageNumbers.length > 0}
                    <nav aria-label="PDF 页码索引" class="grid grid-cols-4 gap-1.5 sm:grid-cols-5">
                        {#each filteredPageNumbers as number (number)}
                            <button
                                type="button"
                                class={`h-10 min-w-0 rounded-md px-1 text-xs font-semibold tabular-nums transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-[var(--primary)] ${number === pageNumber ? "bg-[var(--primary)] text-white" : "bg-[var(--btn-regular-bg)] text-75 hover:text-[var(--primary)]"}`}
                                aria-current={number === pageNumber ? "page" : undefined}
                                aria-label={`第 ${number} 页`}
                                title={`第 ${number} 页${pageDisplayLabel(number) !== String(number) ? ` · ${pageDisplayLabel(number)}` : ""}`}
                                on:click={() => jumpToIndexedPage(number)}
                            >
                                <span class="block truncate">{pageDisplayLabel(number)}</span>
                            </button>
                        {/each}
                    </nav>
                {:else}
                    <div class="flex h-32 flex-col items-center justify-center px-4 text-center text-50">
                        <Icon icon="material-symbols:search-off-rounded" width="26" />
                        <p class="mt-2 text-sm">没有匹配的页码</p>
                    </div>
                {/if}
            {/if}
            {/if}
        </div>

        <div class="flex min-h-11 shrink-0 items-center justify-between border-t border-black/5 px-4 text-xs text-40 dark:border-white/10">
            <span>第 {pageNumber} / {pageCount} 页</span>
            <span class="font-semibold tabular-nums text-50">{readingPercent}%</span>
        </div>
    </div>

    {#if resumeNotice}
        <div class="pointer-events-none absolute bottom-4 right-4 z-20 rounded-lg bg-black/75 px-3 py-2 text-xs font-medium text-white shadow-lg" aria-live="polite">
            {resumeNotice}
        </div>
    {/if}
</section>

<style>
    :global(.pdf-reader-shell:fullscreen) {
        height: 100dvh;
        border-radius: 0;
        background: var(--page-bg);
    }

    :global(.pdf-reader-shell:fullscreen .pdf-viewer-stage) {
        height: calc(100dvh - 6.5rem);
        min-height: 0;
        max-height: none;
    }

    :global(.pdf-viewer-stage) {
        scrollbar-color: color-mix(in srgb, var(--primary) 55%, transparent)
            transparent;
        scrollbar-width: thin;
    }

    :global(.pdf-viewer-stage::-webkit-scrollbar) {
        width: 6px;
        height: 6px;
    }

    :global(.pdf-viewer-stage::-webkit-scrollbar-thumb) {
        border-radius: 999px;
        background: color-mix(in srgb, var(--primary) 55%, transparent);
    }

    @media (min-width: 640px) {
        :global(.pdf-reader-shell:fullscreen .pdf-viewer-stage) {
            height: calc(100dvh - 7.75rem);
        }
    }

    @media (max-width: 767px) {
        :global(html:has(.pdf-reader-shell)),
        :global(body:has(.pdf-reader-shell)) {
            height: 100%;
            overflow: hidden;
        }

        :global(body:has(.pdf-reader-shell) #top-row),
        :global(body:has(.pdf-reader-shell) #banner-wrapper),
        :global(body:has(.pdf-reader-shell) #banner-credit),
        :global(body:has(.pdf-reader-shell) #sidebar),
        :global(body:has(.pdf-reader-shell) .footer),
        :global(body:has(.pdf-reader-shell) .back-to-top-wrapper) {
            display: none !important;
        }

        :global(body:has(.pdf-reader-shell) #main-content) {
            position: fixed;
            inset: 0;
            top: 0 !important;
            z-index: 60;
            height: 100dvh;
        }

        :global(body:has(.pdf-reader-shell) #main-content > div),
        :global(body:has(.pdf-reader-shell) #main-grid) {
            height: 100%;
        }

        :global(body:has(.pdf-reader-shell) #main-grid) {
            display: block;
            padding: 0;
            transform: none !important;
        }

        :global(body:has(.pdf-reader-shell) #swup-container),
        :global(body:has(.pdf-reader-shell) #content-wrapper),
        :global(body:has(.pdf-reader-shell) .pdf-reader-shell),
        :global(body:has(.pdf-reader-shell) .pdf-reader-shell > .card-base) {
            height: 100%;
        }

        :global(body:has(.pdf-reader-shell) .pdf-reader-shell),
        :global(body:has(.pdf-reader-shell) .pdf-reader-shell > .card-base) {
            border-radius: 0;
        }

        :global(body:has(.pdf-reader-shell) .pdf-viewer-stage) {
            height: calc(100dvh - 6.5rem);
            min-height: 0;
            max-height: none;
        }
    }
</style>
