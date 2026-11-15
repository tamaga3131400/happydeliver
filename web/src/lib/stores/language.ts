import { browser } from "$app/environment";
import { derived, writable } from "svelte/store";

type Language = "de" | "en";
const storageKey = "deliver-zenmail-language";

function initialLanguage(): Language {
    if (!browser) return "en";

    try {
        const stored = localStorage.getItem(storageKey);
        if (stored === "de" || stored === "en") return stored;
    } catch {
        // The language selector also works when storage is unavailable.
    }

    return navigator.language.toLowerCase().split("-")[0] === "de" ? "de" : "en";
}

export const language = writable<Language>(initialLanguage());
export const t = derived(
    language,
    ($language) => (english: string, german: string) => ($language === "de" ? german : english),
);

if (browser) {
    language.subscribe((value) => {
        document.documentElement.lang = value;
        try {
            localStorage.setItem(storageKey, value);
        } catch {
            // Keep the in-memory choice if storage is blocked.
        }
    });
}
