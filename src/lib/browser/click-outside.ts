/**
 * Sets up click-outside-to-close behavior for a panel
 * @param panelId - ID of the panel element to close
 * @param ignores - Array of element IDs that should not trigger close when clicked
 * @param onClose - Optional callback fired when the panel is closed
 */
export function setClickOutsideToClose(
    panelId: string,
    ignores: string[],
    onClose?: () => void,
) {
    document.addEventListener("click", (event) => {
        const panelDom = document.getElementById(panelId);
        if (!panelDom) return;

        const tDom = event.target;
        if (!(tDom instanceof Node)) return; // Ensure the event target is an HTML Node

        // Ignore clicks on any of the "ignore" elements or their children
        for (const ig of ignores) {
            const ie = document.getElementById(ig);
            if (ie && (ie === tDom || ie.contains(tDom))) {
                return;
            }
        }

        // Click is outside the panel + ignores -> close the panel
        panelDom.classList.add("float-panel-closed");
        onClose?.();
    });
}

/**
 * Initialize click-outside handlers for common panels
 */
export function initClickOutsideHandlers() {
    setClickOutsideToClose("display-setting", [
        "display-setting",
        "display-settings-switch",
    ]);

    setClickOutsideToClose("nav-menu-panel", [
        "nav-menu-panel",
        "nav-menu-switch",
    ]);

    setClickOutsideToClose("search-panel", [
        "search-panel",
        "search-bar",
        "search-switch",
    ]);
}
