<script lang="ts">
    import { appConfig } from "$lib/stores/config";
</script>

{#if $appConfig.operator}
    <address class="mb-0">
        {$appConfig.operator.name}
        {#each ($appConfig.operator.address ?? "")
            .split("\n")
            .filter((line) => line.trim()) as line}
            <br />{line.trim()}
        {/each}
    </address>
{:else}
    <p class="text-muted">Die Angaben zum Betreiber sind noch nicht eingerichtet.</p>
{/if}
