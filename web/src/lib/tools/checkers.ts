// Checker tools. Network checks run on the server (/api/tools/<slug>),
// the password and file checks run only in the browser.

import type { ZxcvbnResult } from "@zxcvbn-ts/core";

import type { Text } from "./devtools";

export interface CheckRow {
    label: Text;
    value?: string;
    note?: Text;
    status?: "ok" | "warn" | "bad";
}

export interface CheckSection {
    title: Text;
    rows: CheckRow[];
}

export interface CheckResult {
    sections: CheckSection[];
}

export interface Checker {
    slug: string;
    icon: string;
    title: Text;
    description: Text;
    input: "text" | "password" | "file";
    placeholder?: string;
    example?: string;
    ports?: string[];
    local?: (value: string | File, language: "de" | "en") => Promise<CheckResult>;
}

const T = (en: string, de: string): Text => [en, de];

// Password strength

type Zxcvbn = { check: (password: string) => ZxcvbnResult };
const zxcvbn: Partial<Record<"de" | "en", Zxcvbn>> = {};

async function passwordStrength(value: string | File, language: "de" | "en"): Promise<CheckResult> {
    const password = String(value);
    if (!zxcvbn[language]) {
        const [{ ZxcvbnFactory }, common, en, de] = await Promise.all([
            import("@zxcvbn-ts/core"),
            import("@zxcvbn-ts/language-common"),
            import("@zxcvbn-ts/language-en"),
            import("@zxcvbn-ts/language-de"),
        ]);
        zxcvbn[language] = new ZxcvbnFactory({
            translations: language === "de" ? de.translations : en.translations,
            graphs: common.adjacencyGraphs,
            dictionary: { ...common.dictionary, ...en.dictionary, ...de.dictionary },
        });
    }
    const result = zxcvbn[language]!.check(password);
    const levels: Text[] = [
        T("very weak", "sehr schwach"),
        T("weak", "schwach"),
        T("fair", "mittel"),
        T("strong", "stark"),
        T("very strong", "sehr stark"),
    ];
    const status = (["bad", "bad", "warn", "ok", "ok"] as const)[result.score];
    const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((r) => r.test(password)).length;
    const rows: CheckRow[] = [
        { label: T("Rating", "Bewertung"), note: levels[result.score], status },
        { label: T("Length", "Länge"), value: `${[...password].length}`, status: [...password].length >= 12 ? "ok" : "warn" },
        { label: T("Character types", "Zeichenarten"), value: `${classes} / 4` },
        { label: T("Guesses needed", "Nötige Rateversuche"), value: `≈ 10^${Math.round(result.guessesLog10)}` },
        {
            label: T("Online attack (10/s)", "Online-Angriff (10/s)"),
            value: result.crackTimes.onlineNoThrottlingXPerSecond.display,
        },
        {
            label: T("Offline attack, fast hash (10¹⁰/s)", "Offline-Angriff, schneller Hash (10¹⁰/s)"),
            value: result.crackTimes.offlineFastHashingXPerSecond.display,
        },
    ];
    if (result.feedback.warning) {
        rows.push({ label: T("Warning", "Warnung"), value: result.feedback.warning, status: "warn" });
    }
    for (const suggestion of result.feedback.suggestions) {
        rows.push({ label: T("Tip", "Tipp"), value: suggestion });
    }
    return { sections: [{ title: T("Password strength", "Passwortstärke"), rows }] };
}

// File type

function formatSize(bytes: number): string {
    const units = ["B", "KB", "MB", "GB"];
    let size = bytes;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) {
        size /= 1024;
        unit++;
    }
    return `${size.toFixed(unit ? 1 : 0)} ${units[unit]} (${bytes.toLocaleString()} B)`;
}

async function fileType(value: string | File): Promise<CheckResult> {
    const file = value as File;
    const { fileTypeFromBlob } = await import("file-type");
    const detected = await fileTypeFromBlob(file);
    const extension = file.name.includes(".") ? file.name.split(".").pop()!.toLowerCase() : "";
    const rows: CheckRow[] = [
        { label: T("File name", "Dateiname"), value: file.name },
        { label: T("Size", "Größe"), value: formatSize(file.size) },
        {
            label: T("Type by name (browser)", "Typ laut Name (Browser)"),
            value: file.type || undefined,
            note: file.type ? undefined : T("unknown", "unbekannt"),
        },
    ];
    if (detected) {
        const matches = extension === detected.ext || file.type === detected.mime;
        rows.push(
            { label: T("Type by content", "Typ laut Inhalt"), value: detected.mime, status: matches ? "ok" : "warn" },
            { label: T("Expected extension", "Passende Endung"), value: `.${detected.ext}` },
        );
        if (!matches) {
            rows.push({
                label: T("Hint", "Hinweis"),
                note: T(
                    "The file name does not match the content. Be careful with such files.",
                    "Dateiname und Inhalt passen nicht zusammen. Bei solchen Dateien ist Vorsicht geboten.",
                ),
                status: "warn",
            });
        }
    } else {
        rows.push({
            label: T("Type by content", "Typ laut Inhalt"),
            note: T("not recognised (plain text or unknown format)", "nicht erkannt (Text oder unbekanntes Format)"),
        });
    }
    if (file.size <= 256 * 1024 * 1024) {
        const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
        const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
        rows.push({ label: T("SHA-256", "SHA-256"), value: hex });
    }
    return { sections: [{ title: T("File", "Datei"), rows }] };
}

export const checkers: Checker[] = [
    {
        slug: "dns-lookup",
        icon: "diagram-3",
        title: T("DNS lookup", "DNS-Abfrage"),
        description: T(
            "A, AAAA, MX, NS and TXT records plus SPF, DMARC, MTA-STS, TLS reporting and BIMI.",
            "A-, AAAA-, MX-, NS- und TXT-Einträge sowie SPF, DMARC, MTA-STS, TLS-Berichte und BIMI.",
        ),
        input: "text",
        placeholder: "example.com",
        example: "deliver.zenmail.eu",
    },
    {
        slug: "ssl-lookup",
        icon: "shield-lock",
        title: T("SSL certificate check", "SSL-Zertifikat prüfen"),
        description: T(
            "Certificate, validity, chain and TLS version – also for mail ports 465, 993 and 995.",
            "Zertifikat, Gültigkeit, Kette und TLS-Version – auch für die Mail-Ports 465, 993 und 995.",
        ),
        input: "text",
        placeholder: "example.com",
        example: "deliver.zenmail.eu",
        ports: ["443", "465", "993", "995", "8443"],
    },
    {
        slug: "ip-lookup",
        icon: "hdd-network",
        title: T("IP lookup", "IP-Abfrage"),
        description: T(
            "Reverse DNS, forward confirmation, network, ASN and operator of an IP address or domain.",
            "Reverse DNS, Vorwärtsbestätigung, Netz, ASN und Betreiber einer IP-Adresse oder Domain.",
        ),
        input: "text",
        placeholder: "192.0.2.1 / example.com",
        example: "1.1.1.1",
    },
    {
        slug: "whois-lookup",
        icon: "person-vcard",
        title: T("Whois / RDAP lookup", "Whois-/RDAP-Abfrage"),
        description: T(
            "Registrar, dates, status and name servers of a domain, or the owner of an IP network.",
            "Registrar, Daten, Status und Nameserver einer Domain oder Inhaber eines IP-Netzes.",
        ),
        input: "text",
        placeholder: "example.com / 192.0.2.1",
        example: "zenmail.eu",
    },
    {
        slug: "http-headers",
        icon: "list-columns",
        title: T("HTTP headers", "HTTP-Header"),
        description: T(
            "Response headers of a URL with an assessment of the security headers.",
            "Antwort-Header einer URL mit Bewertung der Sicherheits-Header.",
        ),
        input: "text",
        placeholder: "https://example.com",
        example: "https://deliver.zenmail.eu",
    },
    {
        slug: "redirect-check",
        icon: "signpost-split",
        title: T("Redirect checker", "Weiterleitungen prüfen"),
        description: T(
            "Follow a URL through all redirects, with status codes and timings.",
            "Eine URL durch alle Weiterleitungen verfolgen, mit Statuscodes und Zeiten.",
        ),
        input: "text",
        placeholder: "http://example.com",
        example: "http://zenmail.eu",
    },
    {
        slug: "meta-tags",
        icon: "tags",
        title: T("Meta tags checker", "Meta-Tags prüfen"),
        description: T(
            "Title, description, canonical URL, Open Graph and X/Twitter tags with hints.",
            "Titel, Beschreibung, kanonische URL, Open-Graph- und X/Twitter-Tags mit Hinweisen.",
        ),
        input: "text",
        placeholder: "https://example.com",
        example: "https://deliver.zenmail.eu",
    },
    {
        slug: "password-strength",
        icon: "key",
        title: T("Password strength", "Passwortstärke"),
        description: T(
            "Realistic strength estimate with dictionaries – runs only in your browser.",
            "Realistische Einschätzung mit Wörterbüchern – läuft nur in deinem Browser.",
        ),
        input: "password",
        local: passwordStrength,
    },
    {
        slug: "file-type",
        icon: "file-earmark-binary",
        title: T("File type checker", "Dateityp prüfen"),
        description: T(
            "Detect the real file type from its content and compute a SHA-256 hash – the file never leaves your browser.",
            "Den echten Dateityp am Inhalt erkennen und SHA-256 berechnen – die Datei verlässt deinen Browser nicht.",
        ),
        input: "file",
        local: (value) => fileType(value),
    },
];

export function findChecker(slug: string | undefined): Checker | undefined {
    return checkers.find((checker) => checker.slug === slug);
}

export async function runRemote(slug: string, query: string, port?: string): Promise<CheckResult> {
    const params = new URLSearchParams({ q: query });
    if (port) params.set("port", port);
    const response = await fetch(`/api/tools/${slug}?${params}`, { headers: { Accept: "application/json" } });
    const body = await response.json().catch(() => null);
    if (!response.ok) {
        const message: Text = body?.message ?? [`Error ${response.status}`, `Fehler ${response.status}`];
        throw message;
    }
    return body as CheckResult;
}
