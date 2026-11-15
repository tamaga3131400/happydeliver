<script lang="ts">
    import { language, t } from "$lib/stores/language";
    import { devTools } from "$lib/tools/devtools";

    let query = $state("");
    let index = $derived($language === "de" ? 1 : 0);
    let visible = $derived(
        devTools.filter((tool) =>
            `${tool.title.join(" ")} ${tool.description.join(" ")}`
                .toLowerCase()
                .includes(query.trim().toLowerCase()),
        ),
    );
</script>

<svelte:head>
    <title>{$t("Developer tools", "Entwickler-Tools")} · Deliver Zenmail</title>
</svelte:head>

<div class="container py-5">
    <div class="text-center mb-4">
        <h1 class="display-5 fw-bold mb-3">
            <i class="bi bi-tools me-2"></i>{$t("Developer tools", "Entwickler-Tools")}
        </h1>
        <p class="lead text-muted mb-1">
            {$t(
                "Format, minify and convert code and text.",
                "Code und Text formatieren, verkleinern und umwandeln.",
            )}
        </p>
        <p class="small text-muted">
            <i class="bi bi-shield-lock me-1"></i>{$t(
                "Everything runs in your browser. Nothing you enter is sent to the server.",
                "Alles läuft in deinem Browser. Deine Eingaben werden nicht an den Server gesendet.",
            )}
        </p>
    </div>

    <div class="row justify-content-center mb-4">
        <div class="col-md-6">
            <label for="tool-search" class="visually-hidden">{$t("Search tools", "Tools durchsuchen")}</label>
            <input
                id="tool-search"
                type="search"
                class="form-control"
                placeholder={$t("Search tools", "Tools durchsuchen")}
                bind:value={query}
            />
        </div>
    </div>

    <div class="row row-cols-1 row-cols-md-2 row-cols-lg-3 g-3">
        {#each visible as tool (tool.slug)}
            <div class="col">
                <a class="card h-100 text-decoration-none tool-card" href="/tools/{tool.slug}">
                    <div class="card-body d-flex gap-3">
                        <i class="bi bi-{tool.icon} fs-3 tool-icon"></i>
                        <div>
                            <h2 class="h6 fw-bold mb-1">{tool.title[index]}</h2>
                            <p class="small text-muted mb-0">{tool.description[index]}</p>
                        </div>
                    </div>
                </a>
            </div>
        {:else}
            <p class="text-center text-muted">{$t("No tool found.", "Kein Tool gefunden.")}</p>
        {/each}
    </div>
</div>

<style>
    .tool-card {
        color: inherit;
        transition:
            transform 0.15s,
            box-shadow 0.15s;
    }

    .tool-card:hover,
    .tool-card:focus-visible {
        transform: translateY(-2px);
        box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.1);
    }

    .tool-icon {
        color: #0f625e;
    }
</style>
