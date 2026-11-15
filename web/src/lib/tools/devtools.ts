// Developer tools that run entirely in the browser. Nothing is sent to the server.

export type Text = [english: string, german: string];

export type ToolResult =
    | { kind: "text"; value: string }
    | { kind: "html"; value: string }
    | { kind: "table"; rows: [string, string][] };

export interface ToolOption {
    key: string;
    label: Text;
    choices?: { value: string; label: Text }[];
    default: string | boolean;
}

export type Options = Record<string, string | boolean>;

export interface DevTool {
    slug: string;
    icon: string;
    title: Text;
    description: Text;
    options?: ToolOption[];
    sample: string | (() => string);
    shrinks?: boolean;
    run: (input: string, options: Options) => Promise<ToolResult> | ToolResult;
}

const text = (value: string): ToolResult => ({ kind: "text", value });

function escapeHtml(value: string): string {
    return value
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

// JSON

export function formatJson(input: string, options: Options): string {
    const value = JSON.parse(input);
    if (options.mode === "minify") return JSON.stringify(value);
    return JSON.stringify(value, null, options.indent === "tab" ? "\t" : Number(options.indent));
}

// BBCode

function safeUrl(raw: string): string | null {
    const value = raw.trim();
    return /^(https?:\/\/|mailto:)[^\s"'<>]+$/i.test(value) ? value : null;
}

export function bbcodeToHtml(input: string): string {
    const blocks: string[] = [];
    let html = escapeHtml(input.replace(/\r\n?/g, "\n")).replace(
        /\[code\]([\s\S]*?)\[\/code\]/gi,
        (_, code: string) => {
            blocks.push(`<pre><code>${code.replace(/^\n|\n$/g, "")}</code></pre>`);
            return `\u0000${blocks.length - 1}\u0000`;
        },
    );

    const simple: [string, string][] = [
        ["b", "strong"],
        ["i", "em"],
        ["u", "u"],
        ["s", "s"],
        ["sub", "sub"],
        ["sup", "sup"],
    ];
    for (const [tag, element] of simple) {
        html = html.replace(
            new RegExp(`\\[${tag}\\]([\\s\\S]*?)\\[\\/${tag}\\]`, "gi"),
            `<${element}>$1</${element}>`,
        );
    }

    let previous;
    do {
        previous = html;
        html = html
            .replace(/\[(center|left|right)\]([\s\S]*?)\[\/\1\]/gi, '<div style="text-align:$1">$2</div>')
            .replace(/\[quote\]([\s\S]*?)\[\/quote\]/gi, "<blockquote>$1</blockquote>")
            .replace(
                /\[quote=([^\]]{1,80})\]([\s\S]*?)\[\/quote\]/gi,
                "<blockquote><cite>$1</cite>$2</blockquote>",
            )
            .replace(/\[color=(#[0-9a-f]{3,8}|[a-z]{3,20})\]([\s\S]*?)\[\/color\]/gi, '<span style="color:$1">$2</span>')
            .replace(/\[size=([1-7])\]([\s\S]*?)\[\/size\]/gi, (_, size: string, inner: string) => {
                return `<span style="font-size:${[0.63, 0.82, 1, 1.13, 1.5, 2, 3][Number(size) - 1]}em">${inner}</span>`;
            })
            .replace(/\[list(=1)?\]([\s\S]*?)\[\/list\]/gi, (_, ordered: string | undefined, inner: string) => {
                const items = inner
                    .split(/\[\*\]/)
                    .slice(1)
                    .map((item) => `<li>${item.trim()}</li>`)
                    .join("");
                const tag = ordered ? "ol" : "ul";
                return `<${tag}>${items}</${tag}>`;
            });
    } while (html !== previous);

    html = html
        .replace(/\[url\]([^[]*?)\[\/url\]/gi, (match, url: string) => {
            const href = safeUrl(url);
            return href ? `<a href="${href}" rel="nofollow noopener">${url}</a>` : match;
        })
        .replace(/\[url=([^\]]+)\]([\s\S]*?)\[\/url\]/gi, (match, url: string, label: string) => {
            const href = safeUrl(url);
            return href ? `<a href="${href}" rel="nofollow noopener">${label}</a>` : match;
        })
        .replace(/\[img\]([^[]*?)\[\/img\]/gi, (match, url: string) => {
            const src = safeUrl(url);
            return src && !src.startsWith("mailto:") ? `<img src="${src}" alt="">` : match;
        })
        .replace(/\[email\]([^[\s]+@[^[\s]+)\[\/email\]/gi, '<a href="mailto:$1">$1</a>')
        .replace(/\n/g, "<br>\n")
        .replace(/(<\/?(?:ul|ol|li|blockquote|div)[^>]*>)<br>\n/g, "$1\n");

    return html.replace(/\u0000(\d+)\u0000/g, (_, index: string) => blocks[Number(index)]);
}

// HTML entities

export function encodeEntities(input: string, all: boolean): string {
    const escaped = escapeHtml(input);
    if (!all) return escaped;
    return Array.from(escaped)
        .map((char) => {
            const code = char.codePointAt(0)!;
            return code > 126 ? `&#x${code.toString(16).toUpperCase()};` : char;
        })
        .join("");
}

function decodeEntities(input: string): string {
    // A textarea parses its content as text, so no markup is created.
    const area = document.createElement("textarea");
    area.innerHTML = input;
    return area.value;
}

// HTML: minify and strip tags

const blockElements = new Set(
    "address article aside blockquote body br dd details dialog div dl dt fieldset figcaption figure footer form h1 h2 h3 h4 h5 h6 head header hr html li link main meta nav ol option p pre section summary table tbody td tfoot th thead title tr ul script style noscript template".split(
        " ",
    ),
);
const rawText = new Set(["pre", "textarea", "script", "style", "code"]);

function parseHtml(input: string): { root: ParentNode; serialize: () => string } {
    if (/<(!doctype|html[\s>])/i.test(input)) {
        const doc = new DOMParser().parseFromString(input, "text/html");
        const doctype = doc.doctype ? `<!DOCTYPE ${doc.doctype.name}>` : "";
        return { root: doc, serialize: () => doctype + doc.documentElement.outerHTML };
    }
    const template = document.createElement("template");
    template.innerHTML = input;
    return { root: template.content, serialize: () => template.innerHTML };
}

function isBlock(node: Node | null): boolean {
    return !node || (node.nodeType === Node.ELEMENT_NODE && blockElements.has(node.nodeName.toLowerCase()));
}

async function minifyHtml(input: string, options: Options): Promise<string> {
    const { root, serialize } = parseHtml(input);
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_COMMENT | NodeFilter.SHOW_TEXT);
    const remove: Node[] = [];

    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
        if (node.nodeType === Node.COMMENT_NODE) {
            if (options.comments && !/^\[if|^\s*\/?ko\b/.test(node.nodeValue ?? "")) remove.push(node);
            continue;
        }
        if (node.parentElement?.closest(Array.from(rawText).join(","))) continue;
        const value = (node.nodeValue ?? "").replace(/\s+/g, " ");
        if (value === " " && (isBlock(node.previousSibling) || isBlock(node.nextSibling))) {
            remove.push(node);
        } else {
            node.nodeValue = value;
        }
    }
    remove.forEach((node) => node.parentNode?.removeChild(node));

    if (options.inline) {
        for (const style of Array.from(root.querySelectorAll("style"))) {
            style.textContent = minifyCss(style.textContent ?? "", true);
        }
        for (const script of Array.from(root.querySelectorAll("script:not([src])"))) {
            const type = script.getAttribute("type");
            if (type && !/^(text|application)\/javascript$|^module$/i.test(type)) continue;
            script.textContent = await minifyJs(script.textContent ?? "", { mangle: true });
        }
    }
    return serialize();
}

function stripTags(input: string, keepLines: boolean): string {
    const doc = new DOMParser().parseFromString(input, "text/html");
    doc.querySelectorAll("script, style, noscript, template").forEach((node) => node.remove());
    if (!keepLines) return (doc.body.textContent ?? "").replace(/\s+/g, " ").trim();

    const lines: string[] = [];
    let current = "";
    const visit = (node: Node) => {
        if (node.nodeType === Node.TEXT_NODE) {
            current += (node.nodeValue ?? "").replace(/\s+/g, " ");
            return;
        }
        const name = node.nodeName.toLowerCase();
        if (name === "br") {
            lines.push(current.trim());
            current = "";
            return;
        }
        node.childNodes.forEach(visit);
        if (blockElements.has(name)) {
            lines.push(current.trim());
            current = "";
        }
    };
    visit(doc.body);
    lines.push(current.trim());
    return lines.join("\n").replace(/\n{3,}/g, "\n\n").trim();
}

// CSS and JavaScript

let csso: typeof import("csso") | undefined;

function minifyCss(input: string, restructure: boolean): string {
    if (!csso) throw new Error("CSS minifier is not loaded");
    return csso.minify(input, { restructure }).css;
}

async function loadCss() {
    csso ??= await import("csso");
}

async function minifyJs(input: string, options: Options): Promise<string> {
    const { minify } = await import("terser");
    const result = await minify(input, {
        compress: true,
        mangle: Boolean(options.mangle),
        module: options.module === true,
        format: { comments: options.license ? /@license|@preserve|^!/ : false },
    });
    return result.code ?? "";
}

// User agent and URL

function rows(entries: [string, string | undefined][]): [string, string][] {
    return entries.filter((entry): entry is [string, string] => Boolean(entry[1]));
}

async function parseUserAgent(input: string): Promise<ToolResult> {
    const { UAParser } = await import("ua-parser-js");
    const ua = new UAParser(input.trim()).getResult();
    const join = (...parts: (string | undefined)[]) => parts.filter(Boolean).join(" ");
    return {
        kind: "table",
        rows: rows([
            ["Browser", join(ua.browser.name, ua.browser.version)],
            ["Engine", join(ua.engine.name, ua.engine.version)],
            ["OS", join(ua.os.name, ua.os.version)],
            ["Device", join(ua.device.vendor, ua.device.model) || undefined],
            ["Device type", ua.device.type ?? "desktop"],
            ["CPU", ua.cpu.architecture],
        ]),
    };
}

export function parseUrl(input: string): [string, string][] {
    const raw = input.trim();
    let url: URL;
    try {
        url = new URL(raw);
    } catch {
        url = new URL(`https://${raw}`);
    }
    const params = Array.from(url.searchParams).map(
        ([key, value]) => [`?${key}`, value] as [string, string],
    );
    return [
        ...rows([
            ["Protocol", url.protocol],
            ["Username", decodeURIComponent(url.username)],
            ["Password", url.password ? "••••••" : undefined],
            ["Host", url.hostname],
            ["Port", url.port],
            ["Path", decodeURIComponent(url.pathname)],
            ["Query", url.search],
            ["Fragment", url.hash],
            ["Origin", url.origin],
        ]),
        ...params,
    ];
}

// Tool list

export const devTools: DevTool[] = [
    {
        slug: "json",
        icon: "braces",
        title: ["JSON validator & formatter", "JSON prüfen & formatieren"],
        description: ["Validate JSON, then format or minify it.", "JSON prüfen und lesbar formatieren oder verkleinern."],
        options: [
            {
                key: "mode",
                label: ["Mode", "Modus"],
                default: "format",
                choices: [
                    { value: "format", label: ["Format", "Formatieren"] },
                    { value: "minify", label: ["Minify", "Verkleinern"] },
                ],
            },
            {
                key: "indent",
                label: ["Indent", "Einrückung"],
                default: "2",
                choices: [
                    { value: "2", label: ["2 spaces", "2 Leerzeichen"] },
                    { value: "4", label: ["4 spaces", "4 Leerzeichen"] },
                    { value: "tab", label: ["Tab", "Tabulator"] },
                ],
            },
        ],
        sample: '{"name":"Deliver Zenmail","checks":["SPF","DKIM","DMARC"],"score":{"max":20}}',
        run: (input, options) => text(formatJson(input, options)),
    },
    {
        slug: "html-minifier",
        icon: "filetype-html",
        title: ["HTML minifier", "HTML verkleinern"],
        description: [
            "Remove comments and needless whitespace while keeping pre, textarea and scripts intact.",
            "Kommentare und überflüssige Leerzeichen entfernen; pre, textarea und Skripte bleiben unverändert.",
        ],
        options: [
            { key: "comments", label: ["Remove comments", "Kommentare entfernen"], default: true },
            { key: "inline", label: ["Minify inline CSS and JS", "Eingebettetes CSS und JS verkleinern"], default: true },
        ],
        sample: '<!-- Navigation -->\n<nav class="menu">\n    <a href="/">Start</a>\n    <a href="/tools/">Tools</a>\n</nav>\n<style>\n    .menu { display: flex; gap: 1rem; }\n</style>',
        shrinks: true,
        run: async (input, options) => {
            if (options.inline) await loadCss();
            return text(await minifyHtml(input, options));
        },
    },
    {
        slug: "markdown-to-html",
        icon: "markdown",
        title: ["Markdown to HTML", "Markdown zu HTML"],
        description: ["Convert Markdown (GitHub flavour) to HTML with a safe preview.", "Markdown (GitHub-Variante) in HTML umwandeln, mit sicherer Vorschau."],
        options: [{ key: "breaks", label: ["Line breaks as <br>", "Zeilenumbrüche als <br>"], default: false }],
        sample: "# Zenmail\n\n**Tested:** SPF, DKIM and DMARC.\n\n- [x] Send test email\n- [ ] Fix DNS\n\n| Check | Result |\n| --- | --- |\n| SPF | pass |",
        run: async (input, options) => {
            const { marked } = await import("marked");
            return { kind: "html", value: await marked.parse(input, { gfm: true, breaks: Boolean(options.breaks) }) };
        },
    },
    {
        slug: "bbcode-to-html",
        icon: "chat-square-text",
        title: ["BBCode to HTML", "BBCode zu HTML"],
        description: ["Convert forum BBCode to clean HTML. Only http, https and mailto links are kept.", "Forum-BBCode in sauberes HTML umwandeln. Nur http-, https- und mailto-Links werden übernommen."],
        sample: "[b]Hello[/b] [i]world[/i]\n[url=https://deliver.zenmail.eu]Deliver Zenmail[/url]\n[list]\n[*]SPF\n[*]DKIM\n[/list]\n[quote=Admin]Test your mail first.[/quote]",
        run: (input) => ({ kind: "html", value: bbcodeToHtml(input) }),
    },
    {
        slug: "css-minifier",
        icon: "filetype-css",
        title: ["CSS minifier", "CSS verkleinern"],
        description: ["Minify CSS and optionally merge rules safely.", "CSS verkleinern und Regeln auf Wunsch sicher zusammenführen."],
        options: [{ key: "restructure", label: ["Merge rules", "Regeln zusammenführen"], default: true }],
        sample: ".button {\n    color: #ffffff;\n    margin: 0px 0px 0px 0px;\n}\n\n.button {\n    padding: 8px;\n}",
        shrinks: true,
        run: async (input, options) => {
            await loadCss();
            return text(minifyCss(input, Boolean(options.restructure)));
        },
    },
    {
        slug: "sql-formatter",
        icon: "database",
        title: ["SQL formatter", "SQL formatieren"],
        description: ["Format SQL queries for many dialects.", "SQL-Abfragen für viele Dialekte lesbar formatieren."],
        options: [
            {
                key: "language",
                label: ["Dialect", "Dialekt"],
                default: "sql",
                choices: [
                    ["sql", "Standard SQL"],
                    ["mysql", "MySQL"],
                    ["mariadb", "MariaDB"],
                    ["postgresql", "PostgreSQL"],
                    ["sqlite", "SQLite"],
                    ["tsql", "SQL Server"],
                    ["plsql", "Oracle PL/SQL"],
                    ["bigquery", "BigQuery"],
                ].map(([value, label]) => ({ value, label: [label, label] as Text })),
            },
            {
                key: "case",
                label: ["Keywords", "Schlüsselwörter"],
                default: "upper",
                choices: [
                    { value: "upper", label: ["UPPER", "GROSS"] },
                    { value: "lower", label: ["lower", "klein"] },
                    { value: "preserve", label: ["Keep", "Beibehalten"] },
                ],
            },
        ],
        sample: "select id, domain, score from reports where score < 15 and created_at > now() - interval '10 days' order by created_at desc",
        run: async (input, options) => {
            const { format } = await import("sql-formatter");
            return text(
                format(input, {
                    language: options.language as "sql",
                    keywordCase: options.case as "upper",
                    tabWidth: 4,
                }),
            );
        },
    },
    {
        slug: "js-minifier",
        icon: "filetype-js",
        title: ["JavaScript minifier", "JavaScript verkleinern"],
        description: ["Minify modern JavaScript with Terser.", "Modernes JavaScript mit Terser verkleinern."],
        options: [
            { key: "mangle", label: ["Shorten names", "Namen kürzen"], default: true },
            { key: "module", label: ["ES module", "ES-Modul"], default: false },
            { key: "license", label: ["Keep license comments", "Lizenzkommentare behalten"], default: true },
        ],
        sample: "/*! Demo */\nfunction greet(name) {\n    const message = `Hello, ${name}!`;\n    console.log(message);\n    return message;\n}\ngreet('Zenmail');",
        shrinks: true,
        run: async (input, options) => text(await minifyJs(input, options)),
    },
    {
        slug: "html-entities",
        icon: "code-slash",
        title: ["HTML entity converter", "HTML-Entities umwandeln"],
        description: ["Encode text as HTML entities or decode entities back to text.", "Text in HTML-Entities umwandeln oder Entities zurück in Text."],
        options: [
            {
                key: "mode",
                label: ["Mode", "Modus"],
                default: "encode",
                choices: [
                    { value: "encode", label: ["Encode", "Kodieren"] },
                    { value: "decode", label: ["Decode", "Dekodieren"] },
                ],
            },
            { key: "all", label: ["Also encode non-ASCII", "Auch Nicht-ASCII kodieren"], default: false },
        ],
        sample: '<a href="?a=1&b=2">Grüße & „Zitat"</a>',
        run: (input, options) =>
            text(options.mode === "decode" ? decodeEntities(input) : encodeEntities(input, Boolean(options.all))),
    },
    {
        slug: "html-tag-remover",
        icon: "eraser",
        title: ["HTML tag remover", "HTML-Tags entfernen"],
        description: ["Extract plain text from HTML. Scripts and styles are dropped.", "Reinen Text aus HTML gewinnen. Skripte und Styles werden entfernt."],
        options: [{ key: "lines", label: ["Keep line breaks", "Zeilenumbrüche behalten"], default: true }],
        sample: "<h1>Report</h1><p>SPF: <b>pass</b><br>DKIM: <b>pass</b></p><script>alert(1)</script><ul><li>DMARC</li><li>BIMI</li></ul>",
        run: (input, options) => text(stripTags(input, Boolean(options.lines))),
    },
    {
        slug: "user-agent-parser",
        icon: "window-desktop",
        title: ["User agent parser", "User-Agent analysieren"],
        description: ["Detect browser, engine, operating system and device from a user agent.", "Browser, Engine, Betriebssystem und Gerät aus einem User-Agent erkennen."],
        sample: () => (typeof navigator === "undefined" ? "" : navigator.userAgent),
        run: (input) => parseUserAgent(input),
    },
    {
        slug: "url-parser",
        icon: "link-45deg",
        title: ["URL parser", "URL zerlegen"],
        description: ["Split a URL into its parts and decode all query parameters.", "Eine URL in ihre Bestandteile zerlegen und alle Parameter dekodieren."],
        sample: "https://deliver.zenmail.eu/test/abc?utm_source=newsletter&lang=de#score",
        run: (input) => ({ kind: "table", rows: parseUrl(input) }),
    },
];

export function findDevTool(slug: string | undefined): DevTool | undefined {
    return devTools.find((tool) => tool.slug === slug);
}
