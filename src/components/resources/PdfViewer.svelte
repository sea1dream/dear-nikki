<script lang="ts">
import Icon from "@iconify/svelte";
import type {
    PDFDocumentLoadingTask,
    PDFDocumentProxy,
    RenderTask,
} from "pdfjs-dist";
import workerUrl from "pdfjs-dist/build/pdf.worker.min.mjs?url";
import { onDestroy, onMount, tick } from "svelte";
import type { ResourceItem, ResourceListResponse } from "@/types/resources";

let resource: ResourceItem | null = null;
let pdfDocument: PDFDocumentProxy | null = null;
let loadingTask: PDFDocumentLoadingTask | null = null;
let renderTask: RenderTask | null = null;
let canvas: HTMLCanvasElement;
let viewerStage: HTMLDivElement;
let resizeObserver: ResizeObserver | null = null;
let resizeFrame = 0;
let renderSequence = 0;
let loading = true;
let rendering = false;
let loadProgress = 0;
let errorMessage = "";
let pageNumber = 1;
let pageCount = 0;
let pageField = "1";
let zoom = 1;
let actualScale = 1;
let fitWidth = true;
let rotation = 0;
let passwordOpen = false;
let passwordIncorrect = false;
let passwordValue = "";
let submitPassword: ((password: string) => void) | null = null;

function formatBytes(bytes: number): string {
    if (!Number.isFinite(bytes) || bytes < 1) return "0 B";
    const units = ["B", "KB", "MB", "GB"];
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

function setupResizeObserver(): void {
    resizeObserver?.disconnect();
    if (!viewerStage) return;

    resizeObserver = new ResizeObserver(() => {
        if (!fitWidth || !pdfDocument) return;
        window.cancelAnimationFrame(resizeFrame);
        resizeFrame = window.requestAnimationFrame(() => void renderPage());
    });
    resizeObserver.observe(viewerStage);
}

async function renderPage(): Promise<void> {
    if (!pdfDocument || !canvas || !viewerStage) return;

    const sequence = ++renderSequence;
    const previousTask = renderTask;
    previousTask?.cancel();
    if (previousTask) {
        try {
            await previousTask.promise;
        } catch {
            // Cancellation is expected when paging or resizing quickly.
        }
    }
    if (sequence !== renderSequence) return;

    rendering = true;
    try {
        const page = await pdfDocument.getPage(pageNumber);
        if (sequence !== renderSequence) return;

        const baseViewport = page.getViewport({ scale: 1, rotation });
        const availableWidth = Math.max(viewerStage.clientWidth - 32, 240);
        const renderScale = fitWidth
            ? Math.min(Math.max(availableWidth / baseViewport.width, 0.25), 3)
            : zoom;
        actualScale = renderScale;

        const viewport = page.getViewport({ scale: renderScale, rotation });
        const outputScale = Math.min(window.devicePixelRatio || 1, 2);
        const context = canvas.getContext("2d", { alpha: false });
        if (!context) throw new Error("浏览器无法创建 PDF 画布");

        canvas.width = Math.floor(viewport.width * outputScale);
        canvas.height = Math.floor(viewport.height * outputScale);
        canvas.style.width = `${Math.floor(viewport.width)}px`;
        canvas.style.height = `${Math.floor(viewport.height)}px`;

        const currentTask = page.render({
            canvas: null,
            canvasContext: context,
            viewport,
            transform:
                outputScale === 1
                    ? undefined
                    : [outputScale, 0, 0, outputScale, 0, 0],
            background: "rgb(255, 255, 255)",
        });
        renderTask = currentTask;
        await currentTask.promise;
    } catch (error) {
        if (
            !(error instanceof Error) ||
            error.name !== "RenderingCancelledException"
        ) {
            errorMessage =
                error instanceof Error ? error.message : "PDF 页面渲染失败";
        }
    } finally {
        if (sequence === renderSequence) rendering = false;
    }
}

async function openPdf(): Promise<void> {
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

    pdfDocument = await loadingTask.promise;
    pageCount = pdfDocument.numPages;
    pageNumber = 1;
    pageField = "1";
    passwordOpen = false;
    loading = false;
    await tick();
    setupResizeObserver();
    await renderPage();
}

onMount(() => {
    openPdf().catch((error) => {
        errorMessage = error instanceof Error ? error.message : "PDF 加载失败";
        loading = false;
    });
});

onDestroy(() => {
    if (typeof window !== "undefined") {
        window.cancelAnimationFrame(resizeFrame);
    }
    resizeObserver?.disconnect();
    renderTask?.cancel();
    if (loadingTask) {
        void loadingTask.destroy();
    } else if (pdfDocument) {
        void pdfDocument.destroy();
    }
});

function changePage(nextPage: number): void {
    const boundedPage = Math.min(Math.max(Math.round(nextPage), 1), pageCount);
    if (!Number.isFinite(boundedPage) || boundedPage === pageNumber) {
        pageField = String(pageNumber);
        return;
    }
    pageNumber = boundedPage;
    pageField = String(pageNumber);
    void renderPage();
}

function applyPageField(): void {
    changePage(Number(pageField));
}

function adjustZoom(delta: number): void {
    zoom = Math.min(Math.max((fitWidth ? actualScale : zoom) + delta, 0.25), 3);
    fitWidth = false;
    void renderPage();
}

function useFitWidth(): void {
    fitWidth = true;
    void renderPage();
}

function rotatePage(): void {
    rotation = (rotation + 90) % 360;
    void renderPage();
}

async function toggleFullscreen(): Promise<void> {
    if (!viewerStage) return;
    if (document.fullscreenElement) {
        await document.exitFullscreen();
    } else {
        await viewerStage.requestFullscreen();
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

<section class="overflow-hidden rounded-[var(--radius-large)]">
    <div class="card-base overflow-hidden">
        <header class="flex min-h-20 items-center gap-3 border-b border-black/5 px-4 py-4 dark:border-white/10 md:px-6">
            <a
                href="/resources/"
                class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[var(--btn-regular-bg)] text-75 no-underline transition hover:text-[var(--primary)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)]"
                aria-label="返回资源列表"
                title="返回资源列表"
            >
                <Icon icon="material-symbols:arrow-back-rounded" width="22" />
            </a>
            <div class="min-w-0 flex-1">
                <p class="truncate text-base font-bold text-90 md:text-lg" title={resource?.title || "PDF 预览"}>
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
                    class="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[var(--primary)] text-white no-underline transition hover:brightness-105 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)]"
                    aria-label="下载 PDF"
                    title="下载 PDF"
                >
                    <Icon icon="material-symbols:download-rounded" width="21" />
                </a>
            {/if}
        </header>

        {#if loading}
            <div class="flex min-h-[34rem] flex-col items-center justify-center px-5 text-center" aria-live="polite">
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
            <div class="flex min-h-[34rem] items-center justify-center px-5">
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
            <div class="flex min-h-[34rem] flex-col items-center justify-center px-5 text-center">
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
            <div class="flex flex-wrap items-center justify-between gap-2 border-b border-black/5 bg-[var(--btn-regular-bg)]/45 px-3 py-2 dark:border-white/10 md:px-4">
                <div class="flex h-9 items-center gap-1">
                    <button
                        type="button"
                        class="flex h-9 w-9 items-center justify-center rounded-lg text-75 transition hover:bg-[var(--btn-regular-bg)] disabled:opacity-35 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)]"
                        disabled={pageNumber <= 1}
                        on:click={() => changePage(pageNumber - 1)}
                        aria-label="上一页"
                        title="上一页"
                    >
                        <Icon icon="material-symbols:chevron-left-rounded" width="22" />
                    </button>
                    <form class="flex items-center gap-1.5 text-xs text-50" on:submit|preventDefault={applyPageField}>
                        <input
                            bind:value={pageField}
                            type="number"
                            name="pdf-page"
                            min="1"
                            max={pageCount}
                            class="h-8 w-14 rounded-md border border-black/10 bg-[var(--card-bg)] px-1 text-center text-sm font-semibold text-90 outline-none focus-visible:border-[var(--primary)] focus-visible:ring-2 focus-visible:ring-[var(--primary)]/20 dark:border-white/10"
                            aria-label="页码"
                            on:change={applyPageField}
                        />
                        <span>/ {pageCount}</span>
                    </form>
                    <button
                        type="button"
                        class="flex h-9 w-9 items-center justify-center rounded-lg text-75 transition hover:bg-[var(--btn-regular-bg)] disabled:opacity-35 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)]"
                        disabled={pageNumber >= pageCount}
                        on:click={() => changePage(pageNumber + 1)}
                        aria-label="下一页"
                        title="下一页"
                    >
                        <Icon icon="material-symbols:chevron-right-rounded" width="22" />
                    </button>
                </div>

                <div class="flex h-9 items-center gap-1">
                    <button
                        type="button"
                        class="flex h-9 w-9 items-center justify-center rounded-lg text-75 transition hover:bg-[var(--btn-regular-bg)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)]"
                        on:click={() => adjustZoom(-0.15)}
                        aria-label="缩小"
                        title="缩小"
                    >
                        <Icon icon="material-symbols:zoom-out-rounded" width="20" />
                    </button>
                    <span class="w-12 text-center text-xs font-semibold tabular-nums text-50">
                        {Math.round(actualScale * 100)}%
                    </span>
                    <button
                        type="button"
                        class="flex h-9 w-9 items-center justify-center rounded-lg text-75 transition hover:bg-[var(--btn-regular-bg)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)]"
                        on:click={() => adjustZoom(0.15)}
                        aria-label="放大"
                        title="放大"
                    >
                        <Icon icon="material-symbols:zoom-in-rounded" width="20" />
                    </button>
                    <button
                        type="button"
                        class={`flex h-9 w-9 items-center justify-center rounded-lg transition focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)] ${fitWidth ? "bg-[var(--primary)] text-white" : "text-75 hover:bg-[var(--btn-regular-bg)]"}`}
                        on:click={useFitWidth}
                        aria-label="适合宽度"
                        title="适合宽度"
                    >
                        <Icon icon="material-symbols:fit-width-rounded" width="20" />
                    </button>
                    <button
                        type="button"
                        class="flex h-9 w-9 items-center justify-center rounded-lg text-75 transition hover:bg-[var(--btn-regular-bg)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)]"
                        on:click={rotatePage}
                        aria-label="顺时针旋转"
                        title="顺时针旋转"
                    >
                        <Icon icon="material-symbols:rotate-right-rounded" width="20" />
                    </button>
                    <button
                        type="button"
                        class="hidden h-9 w-9 items-center justify-center rounded-lg text-75 transition hover:bg-[var(--btn-regular-bg)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)] sm:flex"
                        on:click={toggleFullscreen}
                        aria-label="全屏阅读"
                        title="全屏阅读"
                    >
                        <Icon icon="material-symbols:fullscreen-rounded" width="22" />
                    </button>
                </div>
            </div>

            <div
                bind:this={viewerStage}
                class="relative flex h-[min(72vh,58rem)] min-h-[30rem] items-start justify-center overflow-auto bg-[#d9dde3] p-4 dark:bg-[#22262c] fullscreen:h-screen fullscreen:max-h-none"
            >
                {#if rendering}
                    <div class="pointer-events-none absolute right-4 top-4 z-10 flex h-8 w-8 items-center justify-center rounded-lg bg-black/60 text-white" aria-label="正在渲染页面">
                        <Icon icon="material-symbols:progress-activity" width="18" class="animate-spin" />
                    </div>
                {/if}
                <canvas
                    bind:this={canvas}
                    class="block max-w-none bg-white shadow-[0_6px_24px_rgba(0,0,0,0.24)]"
                    aria-label={`PDF 第 ${pageNumber} 页`}
                ></canvas>
            </div>
        {/if}
    </div>
</section>
