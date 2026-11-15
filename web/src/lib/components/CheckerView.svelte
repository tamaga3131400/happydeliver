<script lang="ts">
    import { language, t } from "$lib/stores/language";
    import { runRemote, type Checker, type CheckResult } from "$lib/tools/checkers";
    import type { Text } from "$lib/tools/devtools";

    let { checker }: { checker: Checker } = $props();

    let index = $derived($language === "de" ? 1 : 0);
    let query = $state("");
    let port = $state("443");
    let file = $state<File | null>(null);
    let reveal = $state(false);
    let busy = $state(false);
    let result = $state<CheckResult | null>(null);
    let error = $state<Text | null>(null);
    let run = 0;

    // Reset when switching between checkers.
    $effect(() => {
        void checker.slug;
        query = "";
        port = checker.ports?.[0] ?? "";
        file = null;
        result = null;
        error = null;
    });

    async function execute(value: string | File) {
        const id = ++run;
        busy = true;
        error = null;
        try {
            const next = checker.local
                ? await checker.local(value, $language)
                : await runRemote(checker.slug, String(value), checker.ports ? port : undefined);
            if (id === run) result = next;
        } catch (e) {
            if (id === run) {
                result = null;
                error = Array.isArray(e) ? (e as Text) : [String(e), String(e)];
            }
        } finally {
            if (id === run) busy = false;
        }
    }

    function submit(event: SubmitEvent) {
        event.preventDefault();
        if (query.trim()) execute(query.trim());
    }

    // The password check is local and fast, so it runs while typing.
    $effect(() => {
        if (checker.input !== "password") return;
        const value = query;
        void $language;
        if (!value) {
            result = null;
            return;
        }
        const timer = setTimeout(() => execute(value), 150);
        return () => clearTimeout(timer);
    });

    function chooseFile(event: Event) {
        const selected = (event.currentTarget as HTMLInputElement).files?.[0];
        if (selected) {
            file = selected;
            execute(selected);
        }
    }

    function drop(event: DragEvent) {
        event.preventDefault();
        const dropped = event.dataTransfer?.files?.[0];
        if (dropped) {
            file = dropped;
            execute(dropped);
        }
    }

    const badge = { ok: "bi-check-circle-fill text-success", warn: "bi-exclamation-triangle-fill text-warning", bad: "bi-x-circle-fill text-danger" };
    const isIp = (value: string) => /^[0-9a-f:.]+$/i.test(value) && (value.includes(".") || value.includes(":"));
</script>

{#if checker.input === "file"}
    <label
        class="drop-zone d-flex flex-column align-items-center justify-content-center text-center border rounded-3 p-4 mb-4"
        ondragover={(e) => e.preventDefault()}
        ondrop={drop}
    >
        <i class="bi bi-cloud-arrow-up fs-1 tool-icon"></i>
        <span class="fw-semibold">{file ? file.name : $t("Choose a file or drop it here", "Datei auswählen oder hierher ziehen")}</span>
        <span class="small text-muted">{$t("The file is only read in your browser.", "Die Datei wird nur in deinem Browser gelesen.")}</span>
        <input type="file" class="visually-hidden" onchange={chooseFile} />
    </label>
{:else if checker.input === "password"}
    <div class="input-group input-group-lg mb-4">
        <input
            type={reveal ? "text" : "password"}
            class="form-control"
            autocomplete="off"
            spellcheck="false"
            aria-label={$t("Password", "Passwort")}
            placeholder={$t("Enter a password", "Passwort eingeben")}
            bind:value={query}
        />
        <button class="btn btn-outline-secondary" type="button" onclick={() => (reveal = !reveal)}
            aria-label={reveal ? $t("Hide", "Verbergen") : $t("Show", "Anzeigen")}>
            <i class="bi bi-{reveal ? 'eye-slash' : 'eye'}"></i>
        </button>
    </div>
{:else}
    <form class="mb-4" onsubmit={submit}>
        <div class="input-group input-group-lg">
            <input
                type="text"
                class="form-control"
                autocomplete="off"
                spellcheck="false"
                aria-label={checker.title[index]}
                placeholder={checker.placeholder}
                bind:value={query}
            />
            {#if checker.ports}
                <select class="form-select flex-grow-0 w-auto" bind:value={port} aria-label="Port">
                    {#each checker.ports as p (p)}<option value={p}>:{p}</option>{/each}
                </select>
            {/if}
            <button class="btn btn-primary px-4" type="submit" disabled={busy || !query.trim()}>
                {#if busy}<span class="spinner-border spinner-border-sm me-1" role="status"></span>{/if}
                {$t("Check", "Prüfen")}
            </button>
        </div>
        {#if checker.example}
            <button type="button" class="btn btn-link btn-sm px-0" onclick={() => { query = checker.example!; execute(query); }}>
                {$t("Example", "Beispiel")}: {checker.example}
            </button>
        {/if}
    </form>
{/if}

{#if error}
    <div class="alert alert-danger" role="alert"><i class="bi bi-exclamation-triangle me-2"></i>{error[index]}</div>
{/if}

{#if result}
    {#each result.sections as section, i (i)}
        <div class="card mb-3">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h2 class="h6 mb-0 fw-bold">{section.title[index]}</h2>
                {#if checker.slug === "ip-lookup" && isIp(section.title[0])}
                    <a class="btn btn-sm btn-outline-primary" href="/blacklist/{encodeURIComponent(section.title[0])}">
                        <i class="bi bi-shield-exclamation me-1"></i>{$t("Check blacklists", "Sperrlisten prüfen")}
                    </a>
                {/if}
            </div>
            <div class="table-responsive">
                <table class="table table-sm mb-0 align-middle">
                    <tbody>
                        {#each section.rows as r, j (j)}
                            <tr>
                                <th class="small text-nowrap ps-3 label-col">{r.label[index]}</th>
                                <td class="small">
                                    {#if r.status}<i class="bi {badge[r.status]} me-1"></i>{/if}
                                    {#if r.value}<span class="font-monospace value">{r.value}</span>{/if}
                                    {#if r.note}<span class:text-muted={!!r.value} class:d-block={!!r.value}>{r.note[index]}</span>{/if}
                                </td>
                            </tr>
                        {/each}
                    </tbody>
                </table>
            </div>
        </div>
    {/each}
{/if}

<p class="small text-muted mt-3">
    <i class="bi bi-shield-lock me-1"></i>{checker.local
        ? $t("Runs only in your browser. Nothing is sent to the server.", "Läuft nur in deinem Browser. Es wird nichts an den Server gesendet.")
        : $t(
              "The check runs on our server. Inputs are not stored. Limited to 20 checks per minute.",
              "Die Prüfung läuft auf unserem Server. Eingaben werden nicht gespeichert. Höchstens 20 Prüfungen pro Minute.",
          )}
</p>

<style>
    .tool-icon {
        color: #0f625e;
    }

    .drop-zone {
        min-height: 12rem;
        cursor: pointer;
        border-style: dashed !important;
        border-width: 2px !important;
    }

    .label-col {
        width: 30%;
        min-width: 9rem;
        white-space: normal !important;
    }

    .value {
        white-space: pre-wrap;
        word-break: break-word;
    }
</style>
