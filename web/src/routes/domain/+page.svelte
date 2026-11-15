<script lang="ts">
    import { t } from "$lib/stores/language";
    import { goto } from "$app/navigation";

    let domain = $state("");
    let error = $state<"required" | "invalid" | null>(null);

    function handleSubmit() {
        error = null;

        if (!domain.trim()) {
            error = "required";
            return;
        }

        // Basic domain validation
        const domainPattern =
            /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?)*$/;
        if (!domainPattern.test(domain.trim())) {
            error = "invalid";
            return;
        }

        // Navigate to the domain test page
        goto(`/domain/${encodeURIComponent(domain.trim())}`);
    }

    function handleKeyPress(event: KeyboardEvent) {
        if (event.key === "Enter") {
            handleSubmit();
        }
    }
</script>

<svelte:head>
    <title>{$t("Domain Test", "Domain-Test")} · Deliver Zenmail</title>
</svelte:head>

<div class="container py-5">
    <div class="row">
        <div class="col-lg-8 mx-auto">
            <!-- Header -->
            <div class="text-center mb-5">
                <h1 class="display-4 fw-bold mb-3">
                    <i class="bi bi-globe me-2"></i>
                    {$t("Test Domain Configuration", "Domain-Konfiguration prüfen")}
                </h1>
                <p class="lead text-muted">
                    {$t(
                        "Check your domain's email DNS records (MX, SPF, DMARC, BIMI) without sending an email.",
                        "Prüfe die Mail-DNS-Einträge deiner Domain (MX, SPF, DMARC, BIMI) ohne Testmail.",
                    )}
                </p>
            </div>

            <!-- Input Form -->
            <div class="card shadow-lg border-0 mb-5">
                <div class="card-body p-5">
                    <h2 class="h5 mb-4">{$t("Enter Domain Name", "Domainnamen eingeben")}</h2>
                    <div class="input-group input-group-lg mb-3">
                        <span class="input-group-text bg-light">
                            <i class="bi bi-at"></i>
                        </span>
                        <input
                            type="text"
                            class="form-control"
                            placeholder="example.com"
                            bind:value={domain}
                            onkeypress={handleKeyPress}
                            autofocus
                        />
                        <button
                            class="btn btn-primary px-5"
                            onclick={handleSubmit}
                            disabled={!domain.trim()}
                        >
                            <i class="bi bi-search me-2"></i>
                            {$t("Analyze", "Analysieren")}
                        </button>
                    </div>

                    {#if error}
                        <div class="alert alert-danger" role="alert">
                            <i class="bi bi-exclamation-triangle me-2"></i>
                            {error === "required"
                                ? $t("Please enter a domain name", "Gib einen Domainnamen ein.")
                                : $t(
                                      "Please enter a valid domain name (e.g., example.com)",
                                      "Gib einen gültigen Domainnamen ein, zum Beispiel example.com.",
                                  )}
                        </div>
                    {/if}

                    <small class="text-muted">
                        <i class="bi bi-info-circle me-1"></i>
                        {$t(
                            'Enter a domain name like "example.com" or "mail.example.org"',
                            "Gib einen Domainnamen wie „example.com“ oder „mail.example.org“ ein.",
                        )}
                    </small>
                </div>
            </div>

            <!-- Info Section -->
            <div class="row g-4 mb-4">
                <div class="col-md-6">
                    <div class="card h-100 border-0 bg-light">
                        <div class="card-body">
                            <h3 class="h6 mb-3">
                                <i class="bi bi-check-circle-fill text-success me-2"></i>
                                {$t("What's Checked", "Was wird geprüft?")}
                            </h3>
                            <ul class="list-unstyled mb-0 small">
                                <li class="mb-2">
                                    <i class="bi bi-arrow-right me-2"></i>{$t(
                                        "MX Records",
                                        "MX-Einträge",
                                    )}
                                </li>
                                <li class="mb-2">
                                    <i class="bi bi-arrow-right me-2"></i>{$t(
                                        "SPF Records",
                                        "SPF-Einträge",
                                    )}
                                </li>
                                <li class="mb-2">
                                    <i class="bi bi-arrow-right me-2"></i>{$t(
                                        "DMARC Policy",
                                        "DMARC-Richtlinie",
                                    )}
                                </li>
                                <li class="mb-2">
                                    <i class="bi bi-arrow-right me-2"></i>{$t(
                                        "BIMI Support",
                                        "BIMI-Unterstützung",
                                    )}
                                </li>
                                <li class="mb-0">
                                    <i class="bi bi-arrow-right me-2"></i>{$t(
                                        "Disposable Domain Check",
                                        "Prüfung auf Wegwerf-Domains",
                                    )}
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>

                <div class="col-md-6">
                    <div class="card h-100 border-0 bg-light">
                        <div class="card-body">
                            <h3 class="h6 mb-3">
                                <i class="bi bi-info-circle-fill text-primary me-2"></i>
                                {$t("Need More?", "Weitere Prüfungen")}
                            </h3>
                            <p class="small mb-2">
                                {$t(
                                    "For complete email deliverability analysis including:",
                                    "Die vollständige Zustellanalyse umfasst auch",
                                )}
                            </p>
                            <ul class="list-unstyled mb-3 small">
                                <li class="mb-1">
                                    <i class="bi bi-arrow-right me-2"></i>{$t(
                                        "DKIM Verification",
                                        "DKIM-Prüfung",
                                    )}
                                </li>
                                <li class="mb-1">
                                    <i class="bi bi-arrow-right me-2"></i>{$t(
                                        "Content & Header Analysis",
                                        "Analyse von Inhalt und Kopfzeilen",
                                    )}
                                </li>
                                <li class="mb-1">
                                    <i class="bi bi-arrow-right me-2"></i>{$t(
                                        "Spam Scoring",
                                        "Spam-Bewertung",
                                    )}
                                </li>
                                <li class="mb-1">
                                    <i class="bi bi-arrow-right me-2"></i>{$t(
                                        "Blacklist Checks",
                                        "Sperrlistenprüfung",
                                    )}
                                </li>
                            </ul>
                            <a href="/" class="btn btn-sm btn-outline-primary">
                                <i class="bi bi-envelope-plus me-1"></i>
                                {$t("Send Test Email", "Testmail senden")}
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<style>
    .card {
        transition:
            transform 0.2s ease,
            box-shadow 0.2s ease;
    }

    .card:hover {
        transform: translateY(-2px);
        box-shadow: 0 0.5rem 1.5rem rgba(0, 0, 0, 0.1) !important;
    }

    .input-group-lg .form-control {
        font-size: 1.1rem;
    }

    .input-group-text {
        border-right: none;
    }

    .input-group .form-control {
        border-left: none;
        border-right: none;
    }

    .input-group .form-control:focus {
        box-shadow: none;
    }
</style>
