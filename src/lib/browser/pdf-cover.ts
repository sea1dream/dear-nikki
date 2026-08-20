import type { PDFDocumentLoadingTask, PDFPageProxy } from "pdfjs-dist";
import workerUrl from "pdfjs-dist/build/pdf.worker.min.mjs?url";

const COVER_MAX_WIDTH = 640;
const COVER_MAX_HEIGHT = 960;
const COVER_JPEG_QUALITY = 0.84;

function canvasToJpeg(canvas: HTMLCanvasElement): Promise<Blob> {
    return new Promise((resolve, reject) => {
        canvas.toBlob(
            (blob) => {
                if (blob) resolve(blob);
                else reject(new Error("浏览器无法生成封面图片"));
            },
            "image/jpeg",
            COVER_JPEG_QUALITY,
        );
    });
}

export async function createPdfCover(file: File): Promise<Blob> {
    const objectUrl = URL.createObjectURL(file);
    let loadingTask: PDFDocumentLoadingTask | null = null;
    let pdfPage: PDFPageProxy | null = null;
    let canvas: HTMLCanvasElement | null = null;

    try {
        const pdfjs = await import("pdfjs-dist");
        pdfjs.GlobalWorkerOptions.workerSrc = workerUrl;
        loadingTask = pdfjs.getDocument({
            url: objectUrl,
            cMapUrl: "/pdfjs/cmaps/",
            cMapPacked: true,
            standardFontDataUrl: "/pdfjs/standard_fonts/",
            wasmUrl: "/pdfjs/wasm/",
            iccUrl: "/pdfjs/iccs/",
        });

        const passwordError = new Promise<never>((_, reject) => {
            if (!loadingTask) return;
            loadingTask.onPassword = () => {
                reject(new Error("加密 PDF 无法自动生成首页封面"));
            };
        });
        const pdfDocument = await Promise.race([
            loadingTask.promise,
            passwordError,
        ]);
        pdfPage = await pdfDocument.getPage(1);

        const initialViewport = pdfPage.getViewport({ scale: 1 });
        const scale = Math.min(
            COVER_MAX_WIDTH / initialViewport.width,
            COVER_MAX_HEIGHT / initialViewport.height,
        );
        const viewport = pdfPage.getViewport({ scale });
        canvas = document.createElement("canvas");
        canvas.width = Math.max(Math.round(viewport.width), 1);
        canvas.height = Math.max(Math.round(viewport.height), 1);
        const context = canvas.getContext("2d", { alpha: false });
        if (!context) throw new Error("浏览器无法创建封面画布");

        const renderTask = pdfPage.render({
            canvas: null,
            canvasContext: context,
            viewport,
            background: "rgb(255, 255, 255)",
        });
        await renderTask.promise;
        return await canvasToJpeg(canvas);
    } finally {
        pdfPage?.cleanup();
        if (loadingTask) {
            await loadingTask.destroy().catch(() => undefined);
        }
        if (canvas) {
            canvas.width = 1;
            canvas.height = 1;
        }
        URL.revokeObjectURL(objectUrl);
    }
}
