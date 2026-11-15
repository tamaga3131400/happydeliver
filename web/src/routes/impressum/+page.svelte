<script lang="ts">
    import OperatorAddress from "$lib/components/OperatorAddress.svelte";
    import { language } from "$lib/stores/language";
</script>

<svelte:head>
    <title>Impressum · Deliver Zenmail</title>
</svelte:head>

<div class="container py-5" lang="de">
    <div class="legal mx-auto">
        <p class="text-uppercase text-muted small fw-semibold mb-1">Rechtliches</p>
        <h1 class="fw-bold mb-4">Impressum</h1>
        {#if $language !== "de"}
            <p class="text-muted small" lang="en">This page is available in German only.</p>
        {/if}

        <h2 class="h5 fw-bold">Angaben gemäß § 18 Abs. 1 MStV</h2>
        <OperatorAddress />

        <p class="mt-4">
            Deliver Zenmail ist ein privates, nicht kommerzielles Open-Source-Projekt (GNU AGPL v3)
            auf Grundlage von happyDeliver.
        </p>

        <p>Hinweise zum Datenschutz: <a href="/datenschutz/">Datenschutzerklärung</a></p>
    </div>
</div>

<style>
    .legal {
        max-width: 46rem;
    }
</style>
