<script lang="ts">
    import { page } from "$app/state";
    import { t } from "$lib/stores/language";
    import { ErrorDisplay } from "$lib/components";

    let status = $derived(page.status);
    let message = $derived(page.error?.message);

    function getErrorTitle(status: number): string {
        switch (status) {
            case 404:
                return $t("Page Not Found", "Seite nicht gefunden");
            case 403:
                return $t("Access Denied", "Zugriff verweigert");
            case 429:
                return $t("Too Many Requests", "Zu viele Anfragen");
            case 500:
                return $t("Server Error", "Serverfehler");
            case 503:
                return $t("Service Unavailable", "Dienst nicht verfügbar");
            default:
                return $t("Something Went Wrong", "Ein Fehler ist aufgetreten");
        }
    }
</script>

<svelte:head>
    <title>{status} - {getErrorTitle(status)} · Deliver Zenmail</title>
</svelte:head>

<div class="container py-5">
    <ErrorDisplay {status} {message} />
</div>
