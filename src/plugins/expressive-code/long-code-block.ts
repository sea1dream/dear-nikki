import { definePlugin } from "@expressive-code/core";
import type { Element, ElementContent } from "hast";

const DEFAULT_CHUNK_SIZE = 32;
const DEFAULT_LINE_HEIGHT_REM = 1.5;

interface LongCodeBlockOptions {
    chunkSize?: number;
    lineHeightRem?: number;
}

function getClassNames(element: Element): string[] {
    const value = element.properties.className;

    if (Array.isArray(value)) {
        return value.map(String);
    }

    return typeof value === "string" ? value.split(/\s+/) : [];
}

function hasClass(element: Element, className: string): boolean {
    return getClassNames(element).includes(className);
}

function addClass(element: Element, className: string): void {
    const classNames = getClassNames(element);

    if (!classNames.includes(className)) {
        element.properties.className = [...classNames, className];
    }
}

function findElement(
    root: Element,
    predicate: (element: Element) => boolean,
): Element | undefined {
    if (predicate(root)) {
        return root;
    }

    for (const child of root.children) {
        if (child.type !== "element") {
            continue;
        }

        const match = findElement(child, predicate);
        if (match) {
            return match;
        }
    }

    return undefined;
}

function appendStyle(element: Element, declaration: string): void {
    const current = element.properties.style;
    element.properties.style =
        typeof current === "string" && current.length > 0
            ? `${current};${declaration}`
            : declaration;
}

function getVisualColumns(line: string, tabWidth = 4): number {
    let columns = 0;

    for (const character of line) {
        columns += character === "\t" ? tabWidth - (columns % tabWidth) : 1;
    }

    return columns;
}

function createChunk(
    children: ElementContent[],
    lineHeightRem: number,
): Element {
    return {
        type: "element",
        tagName: "div",
        properties: {
            className: ["ec-code-chunk"],
            style: `--ec-chunk-block-size:${children.length * lineHeightRem}rem`,
        },
        children,
    };
}

function chunkRenderedLines(
    codeElement: Element,
    chunkSize: number,
    lineHeightRem: number,
): void {
    const lineElements = codeElement.children.filter(
        (child): child is Element =>
            child.type === "element" && hasClass(child, "ec-line"),
    );

    if (
        lineElements.length <= chunkSize ||
        lineElements.length !== codeElement.children.length
    ) {
        return;
    }

    const chunks: Element[] = [];
    for (let index = 0; index < lineElements.length; index += chunkSize) {
        chunks.push(
            createChunk(
                lineElements.slice(index, index + chunkSize),
                lineHeightRem,
            ),
        );
    }

    codeElement.children = chunks;
}

export function pluginLongCodeBlock({
    chunkSize = DEFAULT_CHUNK_SIZE,
    lineHeightRem = DEFAULT_LINE_HEIGHT_REM,
}: LongCodeBlockOptions = {}) {
    if (!Number.isInteger(chunkSize) || chunkSize < 1) {
        throw new RangeError(
            "Long code block chunkSize must be a positive integer",
        );
    }
    if (!Number.isFinite(lineHeightRem) || lineHeightRem <= 0) {
        throw new RangeError(
            "Long code block lineHeightRem must be a positive number",
        );
    }

    return definePlugin({
        name: "Long Code Block",
        baseStyles: () => `
            .long-code-block pre {
                content-visibility: auto;
                contain-intrinsic-block-size: auto var(--ec-long-code-block-size);
            }

            .long-code-block pre > code {
                min-width: max(100%, var(--ec-long-code-inline-size));
            }

            .long-code-block .ec-code-chunk {
                content-visibility: auto;
                contain-intrinsic-block-size: auto var(--ec-chunk-block-size);
            }
        `,
        hooks: {
            postprocessRenderedBlock: ({ codeBlock, renderData }) => {
                if (codeBlock.metaOptions.getBoolean("long") !== true) {
                    return;
                }

                const lines = codeBlock.code.split("\n");
                const maxColumns = Math.max(...lines.map(getVisualColumns), 1);
                const lineBlockSize = lines.length * lineHeightRem;
                const preElement = findElement(
                    renderData.blockAst,
                    (element) => element.tagName === "pre",
                );
                const codeElement = findElement(
                    renderData.blockAst,
                    (element) => element.tagName === "code",
                );

                addClass(renderData.blockAst, "long-code-block");
                renderData.blockAst.properties["data-pagefind-ignore"] = true;

                if (!preElement || !codeElement) {
                    return;
                }

                appendStyle(
                    preElement,
                    `--ec-long-code-block-size:calc(${lineBlockSize}rem + var(--ec-codePadBlk) + var(--ec-codePadBlk))`,
                );
                appendStyle(
                    codeElement,
                    `--ec-long-code-inline-size:calc(${maxColumns + 10}ch + var(--ec-codePadInl) + var(--ec-codePadInl))`,
                );
                chunkRenderedLines(codeElement, chunkSize, lineHeightRem);
            },
        },
    });
}
