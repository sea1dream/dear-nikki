import type {
    CommentsConfig,
    ExpressiveCodeConfig,
    LicenseConfig,
    NavBarConfig,
    ProfileConfig,
    SiteConfig,
} from "./types/config";
import { LinkPreset } from "./types/config";

export const siteConfig: SiteConfig = {
    title: "seadream",
    subtitle: "liyijieykx99",
    lang: "zh_CN", // Language code, e.g. 'en', 'zh_CN', 'ja', etc.
    themeColor: {
        hue: 275, // Default hue for the theme color, from 0 to 360. e.g. red: 0, teal: 200, cyan: 250, pink: 345
        fixed: false, // Hide the theme color picker for visitors
    },
    banner: {
        enable: true,
        src: "assets/images/theme2.png", // Relative to the /src directory. Relative to the /public directory if it starts with '/'
        position: "center", // Equivalent to object-position, only supports 'top', 'center', 'bottom'. 'center' by default
        credit: {
            enable: false, // Display the credit text of the banner image
            text: "アシマ / Ashima", // Credit text to be displayed
            url: "https://www.pixiv.net/artworks/129563571", // (Optional) URL link to the original artwork or artist's page
        },
    },
    toc: {
        enable: true, // Display the table of contents on the right side of the post
        depth: 2, // Maximum heading depth to show in the table, from 1 to 3
    },
    scrolling: {
        smooth: true, // Enable smooth scrolling by default
    },
    favicon: [
        {
            src: "/favicon/site-icon.png",
            sizes: "192x192",
        },
    ],
};

export const navBarConfig: NavBarConfig = {
    links: [
        LinkPreset.Home,
        LinkPreset.Archive,
        LinkPreset.About,
        LinkPreset.Link, // 友链
        {
            name: "GitHub",
            url: "https://github.com/sea1dream/dear-nikki", // Internal links should not include the base path, as it is automatically added
            external: true, // Show an external link icon and will open in a new tab
        },
    ],
    logo: {
        image: true, // Display an image as logo on the navbar
        src: "assets/images/moon.png", // Relative to the /src directory. Relative to the /public directory if it starts with '/'
    },
};

export const profileConfig: ProfileConfig = {
    avatar: "assets/images/seadream.png", // Relative to the /src directory. Relative to the /public directory if it starts with '/'
    name: "seadream",
    bio: "傻逼李垚吃屎去吧，哎呀你个死妈玩意怎么不去死啊，啊啊啊！",
    links: [
        {
            name: "GitHub",
            icon: "fa6-brands:github", // Visit https://icones.js.org/ for icon codes
            // You will need to install the corresponding icon set if it's not already included
            // `pnpm add @iconify-json/<icon-set-name>`
            url: "https://github.com/sea1dream",
        },
    ],
};

export const licenseConfig: LicenseConfig = {
    enable: true,
    name: "CC BY-NC-SA 4.0",
    url: "https://creativecommons.org/licenses/by-nc-sa/4.0/",
};

export const commentsConfig: CommentsConfig = {
    enable: true,
    repo: "sea1dream/dear-nikki",
    repoId: "R_kgDORboybw",
    category: "General",
    categoryId: "DIC_kwDORboyb84DAbIP",
    mapping: "pathname",
    strict: true,
    reactionsEnabled: true,
    inputPosition: "bottom",
    lang: "zh-CN",
};

export const expressiveCodeConfig: ExpressiveCodeConfig = {
    // Note: Some styles (such as background color) are being overridden, see the astro.config.mjs file.
    // Please select a dark theme, as this blog theme currently only supports dark background color
    theme: "github-dark",
};
