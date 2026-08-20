<script lang="ts">
import Icon from "@iconify/svelte";
import { upload } from "@vercel/blob/client";
import { onMount, tick } from "svelte";
import type {
    ResourceAuthResponse,
    ResourceItem,
    ResourceListResponse,
    ResourceUploadPayload,
} from "@/types/resources";

const MAX_PDF_SIZE = 500 * 1024 * 1024;
const MULTIPART_THRESHOLD = 100 * 1024 * 1024;

let resources: ResourceItem[] = [];
let auth: ResourceAuthResponse = {
    configured: false,
    authenticated: false,
};
let storageConfigured = false;
let loading = true;
let loadError = "";
let query = "";
let notice = "";
let uploadOpen = false;
let uploading = false;
let uploadProgress = 0;
let deletingId = "";
let title = "";
let author = "";
let description = "";
let file: File | null = null;
let titleInput: HTMLInputElement;
let fileInput: HTMLInputElement;

$: normalizedQuery = query.trim().toLocaleLowerCase("zh-CN");
$: filteredResources = normalizedQuery
    ? resources.filter((resource) =>
          [
              resource.title,
              resource.author,
              resource.description,
              resource.originalFilename,
          ].some((value) =>
              value.toLocaleLowerCase("zh-CN").includes(normalizedQuery),
          ),
      )
    : resources;

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

function formatDate(value: string): string {
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return "";
    return new Intl.DateTimeFormat("zh-CN", {
        year: "numeric",
        month: "short",
        day: "numeric",
    }).format(date);
}

async function readError(
    response: Response,
    fallback: string,
): Promise<string> {
    try {
        const body = (await response.json()) as { error?: string };
        return body.error || fallback;
    } catch {
        return fallback;
    }
}

async function loadResources(fresh = false): Promise<void> {
    const suffix = fresh ? `?fresh=${Date.now()}` : "";
    const response = await fetch(`/api/resources/${suffix}`);
    if (!response.ok) {
        throw new Error(await readError(response, "资源列表加载失败"));
    }
    const body = (await response.json()) as ResourceListResponse;
    storageConfigured = body.configured;
    resources = body.resources;
}

async function loadSession(): Promise<void> {
    const response = await fetch("/api/auth/session/", { cache: "no-store" });
    if (!response.ok) return;
    auth = (await response.json()) as ResourceAuthResponse;
}

function consumeAuthResult(): void {
    const url = new URL(window.location.href);
    const result = url.searchParams.get("auth");
    const messages: Record<string, string> = {
        success: "GitHub 身份验证成功",
        forbidden: "该 GitHub 账号没有管理权限",
        cancelled: "已取消 GitHub 登录",
        invalid: "登录请求已失效，请重试",
        failed: "GitHub 登录失败，请重试",
        "not-configured": "管理登录尚未配置",
    };
    if (result && messages[result]) notice = messages[result];
    if (result) {
        url.searchParams.delete("auth");
        window.history.replaceState(
            {},
            "",
            `${url.pathname}${url.search}${url.hash}`,
        );
    }
}

onMount(async () => {
    consumeAuthResult();
    const results = await Promise.allSettled([loadResources(), loadSession()]);
    const resourceResult = results[0];
    if (resourceResult.status === "rejected") {
        loadError =
            resourceResult.reason instanceof Error
                ? resourceResult.reason.message
                : "资源列表加载失败";
    }
    loading = false;
});

function requestUpload(): void {
    notice = "";
    if (!storageConfigured) {
        notice = "资源存储尚未配置";
        return;
    }
    if (!auth.configured) {
        notice = "管理登录尚未配置";
        return;
    }
    if (!auth.authenticated) {
        window.location.assign("/api/auth/login/?returnTo=%2Fresources%2F");
        return;
    }

    uploadOpen = true;
    tick().then(() => titleInput?.focus());
}

function closeUpload(): void {
    if (!uploading) uploadOpen = false;
}

function handleFileChange(event: Event): void {
    const input = event.currentTarget as HTMLInputElement;
    file = input.files?.[0] ?? null;
    if (!file) return;

    if (!title.trim()) {
        title = file.name.replace(/\.pdf$/iu, "").trim();
    }
}

function resetUploadForm(): void {
    title = "";
    author = "";
    description = "";
    file = null;
    uploadProgress = 0;
    if (fileInput) fileInput.value = "";
}

async function submitUpload(): Promise<void> {
    notice = "";
    if (!file || !title.trim()) {
        notice = "请选择 PDF 并填写标题";
        return;
    }
    if (
        file.type !== "application/pdf" &&
        !file.name.toLocaleLowerCase("en-US").endsWith(".pdf")
    ) {
        notice = "只能上传 PDF 文件";
        return;
    }
    if (file.size > MAX_PDF_SIZE) {
        notice = "PDF 不能超过 500 MB";
        return;
    }

    uploading = true;
    uploadProgress = 0;
    const id = crypto.randomUUID();
    const payload: ResourceUploadPayload = {
        id,
        title: title.trim(),
        author: author.trim(),
        description: description.trim(),
        originalFilename: file.name,
    };

    try {
        const blob = await upload(`resources/books/${id}.pdf`, file, {
            access: "public",
            handleUploadUrl: "/api/resources/upload/",
            clientPayload: JSON.stringify(payload),
            contentType: "application/pdf",
            multipart: file.size >= MULTIPART_THRESHOLD,
            onUploadProgress: ({ percentage }) => {
                uploadProgress = Math.round(percentage);
            },
        });

        resources = [
            {
                version: 1,
                ...payload,
                uploadedAt: new Date().toISOString(),
                pathname: blob.pathname,
                url: blob.url,
                downloadUrl: blob.downloadUrl,
                size: file.size,
            },
            ...resources.filter((resource) => resource.id !== id),
        ];
        uploadOpen = false;
        notice = "PDF 已上传";
        resetUploadForm();
        window.setTimeout(() => {
            void loadResources(true).catch(() => undefined);
        }, 2500);
    } catch (error) {
        notice = error instanceof Error ? error.message : "PDF 上传失败";
    } finally {
        uploading = false;
    }
}

async function logout(): Promise<void> {
    const response = await fetch("/api/auth/logout/", { method: "POST" });
    if (!response.ok) {
        notice = await readError(response, "退出登录失败");
        return;
    }
    auth = { ...auth, authenticated: false, user: undefined };
    notice = "已退出管理账号";
}

async function removeResource(resource: ResourceItem): Promise<void> {
    if (!window.confirm(`确定删除《${resource.title}》吗？`)) return;

    deletingId = resource.id;
    const response = await fetch(`/api/resources/${resource.id}/`, {
        method: "DELETE",
    });
    if (response.ok) {
        resources = resources.filter((item) => item.id !== resource.id);
        notice = "资源已删除";
    } else {
        notice = await readError(response, "删除失败");
    }
    deletingId = "";
}

function handleWindowKeydown(event: KeyboardEvent): void {
    if (event.key === "Escape" && uploadOpen) closeUpload();
}
</script>

<svelte:window on:keydown={handleWindowKeydown} />

<section class="overflow-hidden rounded-[var(--radius-large)]">
    <div class="card-base px-5 py-6 md:px-8 md:py-8">
        <header class="flex flex-col gap-5 border-b border-black/5 pb-6 dark:border-white/10 md:flex-row md:items-end md:justify-between">
            <div class="min-w-0">
                <p class="text-sm font-semibold uppercase tracking-[0.3em] text-50">
                    Library
                </p>
                <h1 class="mt-2 text-2xl font-bold text-90 md:text-3xl">
                    资源
                </h1>
                <p class="mt-2 text-sm text-50">
                    {resources.length} 份 PDF
                </p>
            </div>

            <div class="flex flex-wrap items-center gap-2">
                {#if auth.authenticated && auth.user}
                    <div class="flex h-10 min-w-0 items-center gap-2 rounded-lg border border-black/5 bg-[var(--btn-regular-bg)] px-3 dark:border-white/10">
                        <img
                            src={auth.user.avatarUrl}
                            alt=""
                            class="h-6 w-6 rounded-full"
                            referrerpolicy="no-referrer"
                        />
                        <span class="max-w-28 truncate text-sm font-medium text-75">
                            {auth.user.login}
                        </span>
                        <button
                            type="button"
                            class="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-50 transition hover:bg-black/5 hover:text-90 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)] dark:hover:bg-white/10"
                            aria-label="退出管理账号"
                            title="退出管理账号"
                            on:click={logout}
                        >
                            <Icon icon="material-symbols:logout-rounded" width="18" />
                        </button>
                    </div>
                {/if}

                <button
                    type="button"
                    class="inline-flex h-10 items-center gap-2 rounded-lg bg-[var(--primary)] px-4 text-sm font-semibold text-white shadow-sm transition hover:brightness-105 active:scale-[0.98] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)]"
                    on:click={requestUpload}
                >
                    <Icon
                        icon={auth.authenticated
                            ? "material-symbols:upload-file-rounded"
                            : "fa6-brands:github"}
                        width="18"
                    />
                    上传 PDF
                </button>
            </div>
        </header>

        <div class="mt-5 flex items-center gap-3">
            <label class="relative block min-w-0 flex-1">
                <span class="sr-only">搜索资源</span>
                <Icon
                    icon="material-symbols:search-rounded"
                    width="20"
                    class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-30"
                />
                <input
                    type="search"
                    name="resource-search"
                    autocomplete="off"
                    bind:value={query}
                    placeholder="搜索书名、作者或简介"
                    class="h-11 w-full rounded-lg border border-black/5 bg-[var(--btn-regular-bg)] pl-10 pr-4 text-sm text-90 outline-none transition placeholder:text-30 focus-visible:border-[var(--primary)] focus-visible:ring-2 focus-visible:ring-[var(--primary)]/20 dark:border-white/10"
                />
            </label>
        </div>

        {#if notice}
            <p class="mt-4 rounded-lg border border-[var(--primary)]/20 bg-[var(--primary)]/5 px-4 py-3 text-sm text-75" aria-live="polite">
                {notice}
            </p>
        {/if}

        <div class="mt-6">
            {#if loading}
                <div class="space-y-3" aria-label="正在加载资源">
                    {#each Array(3) as _}
                        <div class="h-28 animate-pulse rounded-lg bg-[var(--btn-regular-bg)]"></div>
                    {/each}
                </div>
            {:else if loadError}
                <div class="rounded-lg border border-red-500/20 bg-red-500/5 px-5 py-10 text-center">
                    <Icon icon="material-symbols:error-outline-rounded" width="28" class="mx-auto text-red-500" />
                    <p class="mt-3 text-sm text-75">{loadError}</p>
                    <button
                        type="button"
                        class="mt-4 inline-flex h-9 items-center gap-2 rounded-lg bg-[var(--btn-regular-bg)] px-3 text-sm font-medium text-75 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)]"
                        on:click={() => {
                            loading = true;
                            loadError = "";
                            loadResources(true)
                                .catch((error) => {
                                    loadError = error instanceof Error ? error.message : "资源列表加载失败";
                                })
                                .finally(() => {
                                    loading = false;
                                });
                        }}
                    >
                        <Icon icon="material-symbols:refresh-rounded" width="18" />
                        重新加载
                    </button>
                </div>
            {:else if filteredResources.length === 0}
                <div class="px-5 py-14 text-center">
                    <Icon
                        icon={query
                            ? "material-symbols:search-off-rounded"
                            : "material-symbols:library-books-outline-rounded"}
                        width="34"
                        class="mx-auto text-30"
                    />
                    <p class="mt-3 text-sm font-medium text-50">
                        {query ? "没有匹配的资源" : "暂无资源"}
                    </p>
                </div>
            {:else}
                <div class="divide-y divide-black/5 border-y border-black/5 dark:divide-white/10 dark:border-white/10">
                    {#each filteredResources as resource (resource.id)}
                        <article class="group flex flex-col gap-4 py-5 sm:flex-row sm:items-center">
                            <div class="flex min-w-0 flex-1 items-start gap-4">
                                <div class="flex h-14 w-12 shrink-0 items-center justify-center rounded-lg bg-[var(--primary)]/10 text-[var(--primary)] ring-1 ring-[var(--primary)]/15">
                                    <Icon icon="material-symbols:picture-as-pdf-rounded" width="26" />
                                </div>
                                <div class="min-w-0 flex-1">
                                    <h2 class="break-words text-base font-bold text-90 md:text-lg">
                                        {resource.title}
                                    </h2>
                                    <div class="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-50">
                                        {#if resource.author}
                                            <span>{resource.author}</span>
                                        {/if}
                                        <span>{formatBytes(resource.size)}</span>
                                        <time datetime={resource.uploadedAt}>{formatDate(resource.uploadedAt)}</time>
                                    </div>
                                    {#if resource.description}
                                        <p class="mt-2 line-clamp-2 break-words text-sm leading-6 text-50">
                                            {resource.description}
                                        </p>
                                    {/if}
                                </div>
                            </div>

                            <div class="flex shrink-0 items-center gap-2 pl-16 sm:pl-0">
                                <a
                                    href={`/resources/view/?id=${encodeURIComponent(resource.id)}`}
                                    class="inline-flex h-9 items-center gap-1.5 rounded-lg bg-[var(--primary)] px-3 text-sm font-semibold text-white no-underline transition hover:brightness-105 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)]"
                                >
                                    <Icon icon="material-symbols:menu-book-rounded" width="18" />
                                    预览
                                </a>
                                <a
                                    href={resource.downloadUrl}
                                    class="inline-flex h-9 items-center gap-1.5 rounded-lg bg-[var(--btn-regular-bg)] px-3 text-sm font-semibold text-75 no-underline transition hover:text-[var(--primary)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)]"
                                    title={`下载 ${resource.originalFilename}`}
                                >
                                    <Icon icon="material-symbols:download-rounded" width="18" />
                                    下载
                                </a>
                                {#if auth.authenticated}
                                    <button
                                        type="button"
                                        class="flex h-9 w-9 items-center justify-center rounded-lg text-30 transition hover:bg-red-500/10 hover:text-red-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-500 disabled:cursor-wait disabled:opacity-50"
                                        aria-label={`删除 ${resource.title}`}
                                        title="删除资源"
                                        disabled={deletingId === resource.id}
                                        on:click={() => removeResource(resource)}
                                    >
                                        <Icon
                                            icon={deletingId === resource.id
                                                ? "material-symbols:progress-activity"
                                                : "material-symbols:delete-outline-rounded"}
                                            width="19"
                                            class={deletingId === resource.id ? "animate-spin" : ""}
                                        />
                                    </button>
                                {/if}
                            </div>
                        </article>
                    {/each}
                </div>
            {/if}
        </div>
    </div>
</section>

{#if uploadOpen}
    <div class="fixed inset-0 z-[100] flex items-center justify-center p-4">
        <button
            type="button"
            class="absolute inset-0 cursor-default bg-black/55 backdrop-blur-sm"
            aria-label="关闭上传窗口"
            on:click={closeUpload}
        ></button>
        <dialog
            open
            class="card-base relative z-10 m-0 max-h-[calc(100vh-2rem)] w-full max-w-xl overflow-y-auto rounded-lg border border-black/10 p-5 shadow-2xl dark:border-white/10 md:p-6"
            aria-labelledby="upload-title"
        >
            <header class="flex items-center justify-between gap-4">
                <div>
                    <p class="text-xs font-semibold uppercase tracking-[0.25em] text-50">Owner</p>
                    <h2 id="upload-title" class="mt-1 text-xl font-bold text-90">上传 PDF</h2>
                </div>
                <button
                    type="button"
                    class="flex h-9 w-9 items-center justify-center rounded-lg text-50 transition hover:bg-[var(--btn-regular-bg)] hover:text-90 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)] disabled:opacity-40"
                    aria-label="关闭"
                    title="关闭"
                    disabled={uploading}
                    on:click={closeUpload}
                >
                    <Icon icon="material-symbols:close-rounded" width="22" />
                </button>
            </header>

            <form class="mt-5 space-y-4" on:submit|preventDefault={submitUpload}>
                <label class="block">
                    <span class="mb-1.5 block text-sm font-semibold text-75">PDF 文件</span>
                    <input
                        bind:this={fileInput}
                        type="file"
                        name="resource-file"
                        accept="application/pdf,.pdf"
                        required
                        disabled={uploading}
                        on:change={handleFileChange}
                        class="block w-full rounded-lg border border-black/10 bg-[var(--btn-regular-bg)] p-2 text-sm text-75 file:mr-3 file:rounded-md file:border-0 file:bg-[var(--primary)] file:px-3 file:py-2 file:font-semibold file:text-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)] dark:border-white/10"
                    />
                    <span class="mt-1 block text-xs text-30">最大 500 MB</span>
                </label>

                <label class="block">
                    <span class="mb-1.5 block text-sm font-semibold text-75">标题</span>
                    <input
                        bind:this={titleInput}
                        bind:value={title}
                        type="text"
                        name="resource-title"
                        autocomplete="off"
                        maxlength="160"
                        required
                        disabled={uploading}
                        class="h-11 w-full rounded-lg border border-black/10 bg-[var(--card-bg)] px-3 text-sm text-90 outline-none transition focus-visible:border-[var(--primary)] focus-visible:ring-2 focus-visible:ring-[var(--primary)]/20 dark:border-white/10"
                    />
                </label>

                <label class="block">
                    <span class="mb-1.5 block text-sm font-semibold text-75">作者</span>
                    <input
                        bind:value={author}
                        type="text"
                        name="resource-author"
                        autocomplete="off"
                        maxlength="120"
                        disabled={uploading}
                        class="h-11 w-full rounded-lg border border-black/10 bg-[var(--card-bg)] px-3 text-sm text-90 outline-none transition focus-visible:border-[var(--primary)] focus-visible:ring-2 focus-visible:ring-[var(--primary)]/20 dark:border-white/10"
                    />
                </label>

                <label class="block">
                    <span class="mb-1.5 block text-sm font-semibold text-75">简介</span>
                    <textarea
                        bind:value={description}
                        name="resource-description"
                        rows="4"
                        maxlength="1000"
                        disabled={uploading}
                        class="w-full resize-y rounded-lg border border-black/10 bg-[var(--card-bg)] px-3 py-2.5 text-sm leading-6 text-90 outline-none transition focus-visible:border-[var(--primary)] focus-visible:ring-2 focus-visible:ring-[var(--primary)]/20 dark:border-white/10"
                    ></textarea>
                </label>

                {#if uploading}
                    <div aria-live="polite">
                        <div class="mb-2 flex items-center justify-between text-xs font-medium text-50">
                            <span>正在上传</span>
                            <span>{uploadProgress}%</span>
                        </div>
                        <div class="h-2 overflow-hidden rounded-full bg-[var(--btn-regular-bg)]">
                            <div
                                class="h-full rounded-full bg-[var(--primary)] transition-[width] duration-200"
                                style={`width: ${uploadProgress}%`}
                            ></div>
                        </div>
                    </div>
                {/if}

                <div class="flex justify-end gap-2 pt-2">
                    <button
                        type="button"
                        class="h-10 rounded-lg bg-[var(--btn-regular-bg)] px-4 text-sm font-semibold text-75 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)] disabled:opacity-40"
                        disabled={uploading}
                        on:click={closeUpload}
                    >
                        取消
                    </button>
                    <button
                        type="submit"
                        class="inline-flex h-10 min-w-28 items-center justify-center gap-2 rounded-lg bg-[var(--primary)] px-4 text-sm font-semibold text-white transition hover:brightness-105 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--primary)] disabled:cursor-wait disabled:opacity-60"
                        disabled={uploading}
                    >
                        <Icon
                            icon={uploading
                                ? "material-symbols:progress-activity"
                                : "material-symbols:upload-rounded"}
                            width="18"
                            class={uploading ? "animate-spin" : ""}
                        />
                        {uploading ? "上传中" : "开始上传"}
                    </button>
                </div>
            </form>
        </dialog>
    </div>
{/if}
