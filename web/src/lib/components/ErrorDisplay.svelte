<script lang="ts">
    import { t } from "$lib/stores/language";
    interface Props {
        status: number;
        message?: string;
        showActions?: boolean;
    }

    let { status, message, showActions = true }: Props = $props();

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

    function getErrorDescription(status: number): string {
        switch (status) {
            case 404:
                return $t(
                    "The page you're looking for doesn't exist or has been moved.",
                    "Diese Seite existiert nicht oder wurde verschoben.",
                );
            case 403:
                return $t(
                    "You don't have permission to access this resource.",
                    "Du hast keine Berechtigung für diese Ressource.",
                );
            case 429:
                return $t(
                    "You've made too many requests. Please wait a moment and try again.",
                    "Warte einen Moment und versuche es erneut.",
                );
            case 500:
                return $t(
                    "Our server encountered an error while processing your request.",
                    "Der Server konnte die Anfrage nicht verarbeiten.",
                );
            case 503:
                return $t(
                    "The service is temporarily unavailable. Please try again later.",
                    "Der Dienst ist vorübergehend nicht verfügbar. Versuche es später erneut.",
                );
            default:
                return $t(
                    "An unexpected error occurred. Please try again.",
                    "Ein unerwarteter Fehler ist aufgetreten. Bitte versuche es erneut.",
                );
        }
    }

    function getErrorIcon(status: number): string {
        switch (status) {
            case 404:
                return "bi-search";
            case 403:
                return "bi-shield-lock";
            case 429:
                return "bi-hourglass-split";
            case 500:
                return "bi-exclamation-triangle";
            case 503:
                return "bi-clock-history";
            default:
                return "bi-exclamation-circle";
        }
    }

    let defaultDescription = $derived(getErrorDescription(status));
</script>

<div class="row justify-content-center">
    <div class="col-lg-6 text-center fade-in">
        <!-- Error Icon -->
        <div class="error-icon-wrapper mb-4">
            <i class="bi {getErrorIcon(status)} text-danger"></i>
        </div>

        <!-- Error Status -->
        <h1 class="display-1 fw-bold text-primary mb-3">{status}</h1>

        <!-- Error Title -->
        <h2 class="fw-bold mb-3">{getErrorTitle(status)}</h2>

        <!-- Error Description -->
        <p class="text-muted mb-4">{getErrorDescription(status)}</p>

        <!-- Error Message (if available and different from default) -->
        {#if message && message !== defaultDescription}
            <div class="alert alert-light border mb-4" role="alert">
                <i class="bi bi-info-circle me-2"></i>
                {message}
            </div>
        {/if}

        <!-- Action Buttons -->
        {#if showActions}
            <div class="d-flex flex-column flex-sm-row gap-3 justify-content-center">
                <a href="/" class="btn btn-primary btn-lg px-4">
                    <i class="bi bi-house-door me-2"></i>
                    {$t("Go Home", "Zur Startseite")}
                </a>
                <button
                    class="btn btn-outline-primary btn-lg px-4"
                    onclick={() => window.history.back()}
                >
                    <i class="bi bi-arrow-left me-2"></i>
                    {$t("Go Back", "Zurück")}
                </button>
            </div>
        {/if}

        <!-- Additional Help -->
        {#if status === 404 && showActions}
            <div class="mt-5">
                <p class="text-muted small mb-2">
                    {$t("Looking for something specific?", "Direkt zu")}
                </p>
                <div class="d-flex flex-wrap gap-2 justify-content-center">
                    <a href="/" class="badge bg-light text-dark text-decoration-none"
                        >{$t("Home", "Startseite")}</a
                    >
                    <a href="/#features" class="badge bg-light text-dark text-decoration-none">
                        {$t("Features", "Funktionen")}
                    </a>
                    <a
                        href="https://github.com/tamaga3131400/happydeliver"
                        class="badge bg-light text-dark text-decoration-none"
                    >
                        {$t("Documentation", "Dokumentation")}
                    </a>
                </div>
            </div>
        {/if}
    </div>
</div>

<style>
    .error-icon-wrapper {
        font-size: 6rem;
        line-height: 1;
    }

    .fade-in {
        animation: fadeIn 0.6s ease-out;
    }

    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(20px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    .badge {
        padding: 0.5rem 1rem;
        font-weight: normal;
        transition: all 0.2s ease;
    }

    .badge:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    }
</style>
