/// <reference types="mdast" />
import { h } from "hastscript";

/**
 * @typedef GithubCardProps
 * @property {string} repo - The GitHub repository in the format "owner/repo".
 */

/**
 * Creates a GitHub Card component.
 *
 * @param {GithubCardProps} properties - The properties of the component.
 * @param {import('mdast').RootContent[]} children - The children elements of the component.
 * @returns {import('mdast').Parent} The created GitHub Card component.
 */
export function GithubCardComponent(properties, children) {
    const props = properties || {};

    // Directive must be leaf-only
    if (Array.isArray(children) && children.length !== 0) {
        return h("div", { class: "hidden" }, [
            'Invalid directive. ("github" directive must be leaf type "::github{repo=\\"owner/repo\\"}")',
        ]);
    }

    // Basic repo format validation
    if (typeof props.repo !== "string" || !props.repo.includes("/")) {
        return h(
            "div",
            { class: "hidden" },
            'Invalid repository. ("repo" attribute must be in the format "owner/repo")',
        );
    }

    const repo = props.repo.trim();
    const [owner, repoName] = repo.split("/", 2);

    const cardUuid = `GC${Math.random().toString(36).slice(-6)}`; // Collisions are not important

    const nAvatar = h(`div#${cardUuid}-avatar`, { class: "gc-avatar" });
    const nLanguage = h(
        `span#${cardUuid}-language`,
        { class: "gc-language" },
        "Waiting...",
    );

    const nTitle = h("div", { class: "gc-titlebar" }, [
        h("div", { class: "gc-titlebar-left" }, [
            h("div", { class: "gc-owner" }, [
                nAvatar,
                h("div", { class: "gc-user" }, owner),
            ]),
            h("div", { class: "gc-divider" }, "/"),
            h("div", { class: "gc-repo" }, repoName),
        ]),
        h("div", { class: "github-logo" }),
    ]);

    const nDescription = h(
        `div#${cardUuid}-description`,
        { class: "gc-description" },
        "Waiting for api.github.com...",
    );

    const nStars = h(`div#${cardUuid}-stars`, { class: "gc-stars" }, "00K");
    const nForks = h(`div#${cardUuid}-forks`, { class: "gc-forks" }, "0K");
    const nLicense = h(
        `div#${cardUuid}-license`,
        { class: "gc-license" },
        "no-license",
    );

    const nScript = h(
        `script#${cardUuid}-script`,
        { type: "text/javascript", defer: true },
        `
;(async () => {
  try {
    const response = await fetch('https://api.github.com/repos/${repo}', { referrerPolicy: "no-referrer" });
    if (!response.ok) throw new Error("GitHub API error: " + response.status);
    const data = await response.json();

    const desc = document.getElementById('${cardUuid}-description');
    if (desc) {
      desc.innerText = (data.description || "Description not set").replace(/:[a-zA-Z0-9_]+:/g, '');
    }

    const lang = document.getElementById('${cardUuid}-language');
    if (lang) lang.innerText = data.language || "Unknown";

    const forks = document.getElementById('${cardUuid}-forks');
    if (forks) {
      forks.innerText = Intl.NumberFormat('en-us', { notation: "compact", maximumFractionDigits: 1 })
        .format(data.forks || 0)
        .replaceAll("\\u202f", '');
    }

    const stars = document.getElementById('${cardUuid}-stars');
    if (stars) {
      stars.innerText = Intl.NumberFormat('en-us', { notation: "compact", maximumFractionDigits: 1 })
        .format(data.stargazers_count || 0)
        .replaceAll("\\u202f", '');
    }

    const avatarEl = document.getElementById('${cardUuid}-avatar');
    if (avatarEl && data.owner?.avatar_url) {
      avatarEl.style.backgroundImage = 'url(' + data.owner.avatar_url + ')';
      avatarEl.style.backgroundColor = 'transparent';
    }

    const license = document.getElementById('${cardUuid}-license');
    if (license) license.innerText = data.license?.spdx_id || "no-license";

    const card = document.getElementById('${cardUuid}-card');
    card?.classList.remove("fetch-waiting");
  } catch (err) {
    const c = document.getElementById('${cardUuid}-card');
    c?.classList.add("fetch-error");
    console.warn("[GITHUB-CARD] (Error) Loading card for ${repo} | ${cardUuid}.", err);
  }
})();
    `,
    );

    return h(
        `a#${cardUuid}-card`,
        {
            class: "card-github fetch-waiting no-styling",
            href: `https://github.com/${repo}`,
            target: "_blank",
            repo,
        },
        [
            nTitle,
            nDescription,
            h("div", { class: "gc-infobar" }, [
                nStars,
                nForks,
                nLicense,
                nLanguage,
            ]),
            nScript,
        ],
    );
}
