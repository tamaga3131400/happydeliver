<script lang="ts">
    import { page } from "$app/state";
    import { ErrorDisplay } from "$lib/components";
    import CheckerView from "$lib/components/CheckerView.svelte";
    import { findChecker } from "$lib/tools/checkers";
    import { language, t } from "$lib/stores/language";
    import { findDevTool, type Options, type ToolResult } from "$lib/tools/devtools";

    let tool = $derived(findDevTool(page.params.tool));
    let checker = $derived(findChecker(page.params.tool));
    let index = $derived($language === "de" ? 1 : 0);

    let input = $state("");
    let options = $state<Options>({});
    let result = $state<ToolResult | null>(null);
    let error = $state<string | null>(null);
    let busy = $state(false);
    let view = $state<"code" | "preview">("preview");
    let copied = $state(false);
    let run = 0;

    // Reset the page when switching between tools.
    $effect(() => {
        const current = tool;
        if (!current) return;
        options = Object.fromEntries((current.options ?? []).map((option) => [option.key, option.default]));
        input = typeof current.sample === "function" ? current.sample() : current.sample;
        result = null;
        error = null;
    });

    // Run the tool shortly after the input or options change.
    $effect(() => {
        const current = tool;
        const value = input;
        const opts = { ...options };
        if (!current) return;
        const id = ++run;
        const timer = setTimeout(async () => {
            if (!value.trim()) {
                result = null;
                error = null;
                return;
            }
            busy = true;
            try {
                const next = await current.run(value, opts);
                if (id === run) {
                    result = next;
                    error = null;
                }
            } catch (e) {
                if (id === run) {
                    result = null;
                    error = e instanceof Error ? e.message : String(e);
                }
            } finally {
                if (id === run) busy = false;
            }
        }, 250);
        return () => clearTimeout(timer);
    });

    let output = $derived(result && result.kind !== "table" ? result.value : "");
    let bytesIn = $derived(new TextEncoder().encode(input).length);
    let bytesOut = $derived(new TextEncoder().encode(output).length);

    const previewDocument = (html: string) =>
        `<!doctype html><meta charset="utf-8"><style>body{font:15px/1.5 system-ui,sans-serif;margin:1rem;color:#212529}img{max-width:100%}pre{background:#f1f3f5;padding:.5rem;overflow:auto}blockquote{border-left:3px solid #0f625e;margin-left:0;padding-left:1rem}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:.25rem .5rem}</style>${html}`;

    async function copy() {
        const value =
            result?.kind === "table" ? result.rows.map(([k, v]) => `${k}\t${v}`).join("\n") : output;
        try {
            await navigator.clipboard.writeText(value);
            copied = true;
            setTimeout(() => (copied = false), 1500);
        } catch {
            copied = false;
        }
    }

    function loadSample() {
        if (tool) input = typeof tool.sample === "function" ? tool.sample() : tool.sample;
    }
</script>

<svelte:head>
    <title>{(tool ?? checker)?.title[index] ?? $t("Tool not found", "Tool nicht gefunden")} · Deliver Zenmail</title>
</svelte:head>

{#if checker}
    <div class="container py-4">
        <nav aria-label="breadcrumb" class="mb-3">
            <ol class="breadcrumb small mb-0">
                <li class="breadcrumb-item"><a href="/tools/">{$t("Tools", "Tools")}</a></li>
                <li class="breadcrumb-item active" aria-current="page">{checker.title[index]}</li>
            </ol>
        </nav>
        <div class="col-lg-9 mx-auto px-0">
            <h1 class="h2 fw-bold mb-1"><i class="bi bi-{checker.icon} me-2 tool-icon"></i>{checker.title[index]}</h1>
            <p class="text-muted mb-4">{checker.description[index]}</p>
            <CheckerView {checker} />
        </div>
    </div>
{:else if !tool}
    <ErrorDisplay status={404} />
{:else}
    <div class="container py-4">
        <nav aria-label="breadcrumb" class="mb-3">
            <ol class="breadcrumb small mb-0">
                <li class="breadcrumb-item"><a href="/tools/">{$t("Tools", "Tools")}</a></li>
                <li class="breadcrumb-item active" aria-current="page">{tool.title[index]}</li>
            </ol>
        </nav>

        <h1 class="h2 fw-bold mb-1"><i class="bi bi-{tool.icon} me-2 tool-icon"></i>{tool.title[index]}</h1>
        <p class="text-muted mb-4">{tool.description[index]}</p>

        {#if tool.options?.length}
            <div class="d-flex flex-wrap gap-3 align-items-center mb-3">
                {#each tool.options as option (option.key)}
                    {#if option.choices}
                        <div class="d-flex align-items-center gap-2">
                            <label class="small fw-semibold" for="opt-{option.key}">{option.label[index]}</label>
                            <select
                                id="opt-{option.key}"
                                class="form-select form-select-sm w-auto"
                                bind:value={options[option.key]}
                            >
                                {#each option.choices as choice (choice.value)}
                                    <option value={choice.value}>{choice.label[index]}</option>
                                {/each}
                            </select>
                        </div>
                    {:else}
                        <div class="form-check form-switch mb-0">
                            <input
                                id="opt-{option.key}"
                                class="form-check-input"
                                type="checkbox"
                                checked={Boolean(options[option.key])}
                                onchange={(e) => (options[option.key] = e.currentTarget.checked)}
                            />
                            <label class="form-check-label small" for="opt-{option.key}">{option.label[index]}</label>
                        </div>
                    {/if}
                {/each}
            </div>
        {/if}

        <div class="row g-3">
            <div class="col-lg-6">
                <div class="d-flex justify-content-between align-items-end mb-1">
                    <label for="tool-input" class="fw-semibold">{$t("Input", "Eingabe")}</label>
                    <div class="btn-group btn-group-sm">
                        <button class="btn btn-outline-secondary" onclick={loadSample}>{$t("Example", "Beispiel")}</button>
                        <button class="btn btn-outline-secondary" onclick={() => (input = "")}>{$t("Clear", "Leeren")}</button>
                    </div>
                </div>
                <textarea
                    id="tool-input"
                    class="form-control font-monospace tool-area"
                    spellcheck="false"
                    autocomplete="off"
                    bind:value={input}
                ></textarea>
            </div>

            <div class="col-lg-6">
                <div class="d-flex justify-content-between align-items-end mb-1">
                    <span class="fw-semibold">
                        {$t("Result", "Ergebnis")}
                        {#if busy}<span class="spinner-border spinner-border-sm ms-2" role="status"></span>{/if}
                    </span>
                    <div class="d-flex gap-2">
                        {#if result?.kind === "html"}
                            <div class="btn-group btn-group-sm" role="group">
                                <button class="btn btn-outline-secondary" class:active={view === "preview"} onclick={() => (view = "preview")}>
                                    {$t("Preview", "Vorschau")}
                                </button>
                                <button class="btn btn-outline-secondary" class:active={view === "code"} onclick={() => (view = "code")}>
                                    HTML
                                </button>
                            </div>
                        {/if}
                        <button class="btn btn-sm btn-primary" onclick={copy} disabled={!result}>
                            <i class="bi bi-{copied ? 'check2' : 'clipboard'} me-1"></i>{copied
                                ? $t("Copied", "Kopiert")
                                : $t("Copy", "Kopieren")}
                        </button>
                    </div>
                </div>

                {#if error}
                    <div class="alert alert-danger font-monospace small tool-area mb-0" role="alert">
                        <i class="bi bi-exclamation-triangle me-1"></i>{error}
                    </div>
                {:else if result?.kind === "table"}
                    <div class="table-responsive border rounded tool-area">
                        <table class="table table-sm mb-0">
                            <tbody>
                                {#each result.rows as [key, value], i (i)}
                                    <tr>
                                        <th class="text-nowrap small">{key}</th>
                                        <td class="font-monospace small text-break">{value}</td>
                                    </tr>
                                {/each}
                            </tbody>
                        </table>
                    </div>
                {:else if result?.kind === "html" && view === "preview"}
                    <iframe
                        title={$t("Preview", "Vorschau")}
                        class="w-100 border rounded tool-area bg-white"
                        sandbox=""
                        srcdoc={previewDocument(result.value)}
                    ></iframe>
                {:else}
                    <textarea
                        class="form-control font-monospace tool-area"
                        readonly
                        spellcheck="false"
                        aria-label={$t("Result", "Ergebnis")}
                        value={output}
                    ></textarea>
                {/if}

                {#if tool.shrinks && result && !error && bytesIn > 0}
                    <p class="small text-muted mt-2 mb-0">
                        {bytesIn.toLocaleString()} → {bytesOut.toLocaleString()} Bytes
                        ({Math.round((1 - bytesOut / bytesIn) * 100)} % {$t("smaller", "kleiner")})
                    </p>
                {/if}
            </div>
        </div>

        <p class="small text-muted mt-4">
            <i class="bi bi-shield-lock me-1"></i>{$t(
                "Runs in your browser. Nothing you enter is sent to the server.",
                "Läuft in deinem Browser. Deine Eingaben werden nicht an den Server gesendet.",
            )}
        </p>
    </div>
{/if}

<style>
    .tool-area {
        height: 22rem;
        resize: vertical;
        overflow: auto;
    }

    .tool-icon {
        color: #0f625e;
    }
</style>
