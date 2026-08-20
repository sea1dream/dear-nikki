export function initNavbar() {
    const switchTheme = () => {
        const root = document.documentElement;
        const next = localStorage.theme === "dark" ? "light" : "dark";
        root.classList.toggle("dark", next === "dark");
        localStorage.theme = next;
    };

    const onReady = () => {
        // Optional theme switch (if a button with this id exists)
        document
            .getElementById("scheme-switch")
            ?.addEventListener("click", switchTheme);

        document
            .getElementById("display-settings-switch")
            ?.addEventListener("click", () => {
                document
                    .getElementById("display-setting")
                    ?.classList.toggle("float-panel-closed");
            });

        document
            .getElementById("nav-menu-switch")
            ?.addEventListener("click", () => {
                document
                    .getElementById("nav-menu-panel")
                    ?.classList.toggle("float-panel-closed");
            });
    };

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", onReady, { once: true });
    } else {
        onReady();
    }
}
