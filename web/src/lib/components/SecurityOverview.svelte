<script lang="ts">
    import { onMount } from "svelte";

    import { language, t } from "$lib/stores/language";
    import type { Text } from "$lib/tools/devtools";

    interface Item {
        title: string;
        platform?: string;
        date: string;
        cves?: string[];
        cvss?: number;
        epss?: number;
        exploited?: boolean;
        ransomware?: boolean;
        public_exploit?: boolean;
        unauthenticated?: boolean;
        action: Text;
    }
    interface Category {
        key: string;
        title: Text;
        info: Text;
        items: Item[];
    }

    let index = $derived($language === "de" ? 1 : 0);
    let categories = $state<Category[]>([]);
    let updated = $state<string | null>(null);
    let active = $state("exploited");
    let error = $state<Text | null>(null);
    let loading = $state(true);

    onMount(async () => {
        try {
            const response = await fetch("/api/tools/security-overview", { headers: { Accept: "application/json" } });
            const body = await response.json();
            if (!response.ok) {
                error = body?.message ?? ["Error", "Fehler"];
            } else {
                categories = (body.categories ?? []).map((c: Category) => ({ ...c, items: c.items ?? [] }));
                updated = body.updated;
                active = categories.find((c) => c.items.length)?.key ?? active;
            }
        } catch {
            error = ["The overview could not be loaded.", "Die Übersicht konnte nicht geladen werden."];
        } finally {
            loading = false;
        }
    });

    let current = $derived(categories.find((c) => c.key === active));
    const percent = (value: number) => (value * 100 >= 10 ? Math.round(value * 100) : (value * 100).toFixed(1)) + " %";
    const cvssClass = (score: number) => (score >= 9 ? "bg-danger" : "bg-warning text-dark");
</script>

<div class="alert alert-info small">
    <i class="bi bi-info-circle me-1"></i>{$t(
        "This list helps you find software that needs an update now. It is ranked by active exploitation (CISA), exploit probability (EPSS), severity and age. On purpose it contains no links to exploits.",
        "Die Liste hilft, Software zu finden, die jetzt ein Update braucht. Sortiert wird nach aktiver Ausnutzung (CISA), Ausnutzungswahrscheinlichkeit (EPSS), Schweregrad und Alter. Links zu Exploits gibt es bewusst nicht.",
    )}
</div>

{#if loading}
    <div class="text-center py-5"><span class="spinner-border" role="status"></span></div>
{:else if error}
    <div class="alert alert-warning"><i class="bi bi-hourglass-split me-2"></i>{error[index]}</div>
{:else}
    <div class="d-flex flex-wrap gap-2 mb-3" role="tablist">
        {#each categories as c (c.key)}
            <button
                type="button"
                role="tab"
                aria-selected={active === c.key}
                class="btn btn-sm {active === c.key ? 'btn-primary' : 'btn-outline-secondary'}"
                onclick={() => (active = c.key)}
            >
                {c.title[index]} <span class="badge bg-light text-dark ms-1">{c.items.length}</span>
            </button>
        {/each}
    </div>

    {#if current}
        <p class="text-muted small mb-3">{current.info[index]}</p>
        {#if current.items.length === 0}
            <p class="text-muted">{$t("No entries in this period.", "Keine Einträge in diesem Zeitraum.")}</p>
        {/if}
        <ol class="list-unstyled">
            {#each current.items as item, i (i)}
                <li class="card mb-2">
                    <div class="card-body py-3">
                        <div class="d-flex gap-3">
                            <span class="rank fw-bold">{i + 1}</span>
                            <div class="flex-grow-1 min-w-0">
                                <h2 class="h6 fw-bold mb-1 text-break">{item.title}</h2>
                                <div class="small text-muted mb-2">
                                    {[item.platform, item.date].filter(Boolean).join(" · ")}{#if item.cves?.length}{" · "}<span class="font-monospace">{item.cves.join(", ")}</span>{/if}
                                </div>
                                <div class="d-flex flex-wrap gap-1 mb-2">
                                    {#if item.exploited}
                                        <span class="badge bg-danger"><i class="bi bi-fire me-1"></i>{$t("Actively exploited", "Aktiv ausgenutzt")}</span>
                                    {/if}
                                    {#if item.ransomware}
                                        <span class="badge bg-dark">{$t("Used by ransomware", "Von Ransomware genutzt")}</span>
                                    {/if}
                                    {#if item.cvss}
                                        <span class="badge {cvssClass(item.cvss)}">CVSS {item.cvss.toFixed(1)}</span>
                                    {/if}
                                    {#if item.unauthenticated}
                                        <span class="badge bg-warning text-dark">{$t("No login required", "Ohne Anmeldung ausnutzbar")}</span>
                                    {/if}
                                    {#if item.epss}
                                        <span class="badge bg-secondary" title={$t("Probability of exploitation within 30 days (EPSS)", "Wahrscheinlichkeit einer Ausnutzung in 30 Tagen (EPSS)")}>
                                            EPSS {percent(item.epss)}
                                        </span>
                                    {/if}
                                    {#if item.public_exploit}
                                        <span class="badge bg-light text-dark border">{$t("Public exploit exists", "Öffentlicher Exploit vorhanden")}</span>
                                    {/if}
                                </div>
                                <p class="small mb-0"><i class="bi bi-wrench-adjustable me-1 text-success"></i>{item.action[index]}</p>
                            </div>
                        </div>
                    </div>
                </li>
            {/each}
        </ol>
    {/if}

    <p class="small text-muted mt-4">
        {#if updated}{$t("Updated", "Stand")}: {new Date(updated).toLocaleString($language === "de" ? "de-DE" : "en-GB")} ·{/if}
        {$t("Sources", "Quellen")}: Exploit-DB (OffSec, GPL-2.0), CISA Known Exploited Vulnerabilities, FIRST EPSS, NIST NVD.
        This product uses data from the NVD API but is not endorsed or certified by the NVD.
    </p>
{/if}

<style>
    .rank {
        color: #0f625e;
        min-width: 1.5rem;
        font-size: 1.1rem;
    }

    .min-w-0 {
        min-width: 0;
    }
</style>
