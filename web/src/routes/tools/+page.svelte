<script lang="ts">
    import { language, t } from "$lib/stores/language";
    import { checkers } from "$lib/tools/checkers";
    import { devTools, type Text } from "$lib/tools/devtools";

    type Entry = { slug: string; icon: string; title: Text; description: Text; local?: boolean; href?: string };

    const securityEntries: Entry[] = [
        {
            slug: "security-overview",
            icon: "shield-exclamation",
            title: ["Security situation", "Sicherheitslage"],
            description: [
                "Top 10 urgent vulnerabilities per area – mail servers, WordPress, web apps and more. Updated daily.",
                "Top 10 der dringendsten Schwachstellen je Bereich – Mailserver, WordPress, Webanwendungen und mehr. Täglich aktualisiert.",
            ],
        },
        {
            slug: "blacklist",
            href: "/blacklist/",
            icon: "slash-circle",
            title: ["Blacklist check", "Sperrlisten-Prüfung"],
            description: [
                "Is an IP address listed on spam blacklists (DNSBL)?",
                "Steht eine IP-Adresse auf Spam-Sperrlisten (DNSBL)?",
            ],
        },
    ];

    let query = $state("");
    let index = $derived($language === "de" ? 1 : 0);
    const matches = (entry: Entry) =>
        `${entry.title.join(" ")} ${entry.description.join(" ")}`.toLowerCase().includes(query.trim().toLowerCase());

    let groups = $derived<{ title: string; text: string; entries: Entry[] }[]>([
        {
            title: $t("Security", "Sicherheit"),
            text: $t(
                "Current threats and the reputation of your mail server.",
                "Aktuelle Bedrohungen und der Ruf deines Mailservers.",
            ),
            entries: securityEntries.filter(matches),
        },
        {
            title: $t("Check tools", "Prüf-Tools"),
            text: $t(
                "DNS, certificates, IP addresses, domains and websites.",
                "DNS, Zertifikate, IP-Adressen, Domains und Webseiten.",
            ),
            entries: checkers.map((c) => ({ ...c, local: Boolean(c.local) })).filter(matches),
        },
        {
            title: $t("Developer tools", "Entwickler-Tools"),
            text: $t(
                "Format, minify and convert code. Runs entirely in your browser.",
                "Code formatieren, verkleinern und umwandeln. Läuft vollständig in deinem Browser.",
            ),
            entries: devTools.map((d) => ({ ...d, local: true })).filter(matches),
        },
    ]);
</script>

<svelte:head>
    <title>Tools · Deliver Zenmail</title>
</svelte:head>

<div class="container py-5">
    <div class="text-center mb-4">
        <h1 class="display-5 fw-bold mb-3"><i class="bi bi-tools me-2"></i>Tools</h1>
        <p class="lead text-muted">
            {$t(
                "Useful checks and helpers for email, domains and web development.",
                "Nützliche Prüfungen und Helfer rund um E-Mail, Domains und Webentwicklung.",
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

    {#each groups as group (group.title)}
        {#if group.entries.length}
            <section class="mb-5">
                <h2 class="h4 fw-bold mb-1">{group.title}</h2>
                <p class="text-muted small mb-3">{group.text}</p>
                <div class="row row-cols-1 row-cols-md-2 row-cols-lg-3 g-3">
                    {#each group.entries as tool (tool.slug)}
                        <div class="col">
                            <a class="card h-100 text-decoration-none tool-card" href={tool.href ?? `/tools/${tool.slug}`}>
                                <div class="card-body d-flex gap-3">
                                    <i class="bi bi-{tool.icon} fs-3 tool-icon"></i>
                                    <div>
                                        <h3 class="h6 fw-bold mb-1">{tool.title[index]}</h3>
                                        <p class="small text-muted mb-0">{tool.description[index]}</p>
                                    </div>
                                </div>
                            </a>
                        </div>
                    {/each}
                </div>
            </section>
        {/if}
    {/each}

    {#if groups.every((g) => !g.entries.length)}
        <p class="text-center text-muted">{$t("No tool found.", "Kein Tool gefunden.")}</p>
    {/if}
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
