<script lang="ts">
    import { t } from "$lib/stores/language";
    import { goto } from "$app/navigation";

    import { appConfig } from "$lib/stores/config";

    let ip = $state("");
    let error = $state<"required" | "invalid" | null>(null);

    function handleSubmit() {
        error = null;

        if (!ip.trim()) {
            error = "required";
            return;
        }

        // Basic IPv4/IPv6 validation
        const ipv4Pattern =
            /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6Pattern =
            /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;

        if (!ipv4Pattern.test(ip.trim()) && !ipv6Pattern.test(ip.trim())) {
            error = "invalid";
            return;
        }

        // Navigate to the blacklist check page
        goto(`/blacklist/${encodeURIComponent(ip.trim())}`);
    }

    function handleKeyPress(event: KeyboardEvent) {
        if (event.key === "Enter") {
            handleSubmit();
        }
    }
</script>

<svelte:head>
    <title>{$t("Blacklist Check", "Sperrlistenprüfung")} · Deliver Zenmail</title>
</svelte:head>

<div class="container py-5">
    <div class="row">
        <div class="col-lg-8 mx-auto">
            <!-- Header -->
            <div class="text-center mb-5">
                <h1 class="display-4 fw-bold mb-3">
                    <i class="bi bi-shield-exclamation me-2"></i>
                    {$t("Check IP Blacklist Status", "IP-Adresse auf Sperrlisten prüfen")}
                </h1>
                <p class="lead text-muted">
                    {$t(
                        "Test an IP address against multiple DNS-based blacklists (RBLs) to check its reputation.",
                        "Prüfe den Ruf einer IP-Adresse anhand mehrerer DNS-Sperrlisten (RBLs).",
                    )}
                </p>
            </div>

            <!-- Input Form -->
            <div class="card shadow-lg border-0 mb-5">
                <div class="card-body p-5">
                    <h2 class="h5 mb-4">{$t("Enter IP Address", "IP-Adresse eingeben")}</h2>
                    <div class="input-group input-group-lg mb-3">
                        <span class="input-group-text bg-light">
                            <i class="bi bi-hdd-network"></i>
                        </span>
                        <input
                            type="text"
                            class="form-control"
                            placeholder="192.0.2.1 or 2001:db8::1"
                            bind:value={ip}
                            onkeypress={handleKeyPress}
                            autofocus
                        />
                        <button
                            class="btn btn-primary px-5"
                            onclick={handleSubmit}
                            disabled={!ip.trim()}
                        >
                            <i class="bi bi-search me-2"></i>
                            {$t("Check", "Prüfen")}
                        </button>
                    </div>

                    {#if error}
                        <div class="alert alert-danger" role="alert">
                            <i class="bi bi-exclamation-triangle me-2"></i>
                            {error === "required"
                                ? $t("Please enter an IP address", "Gib eine IP-Adresse ein.")
                                : $t(
                                      "Please enter a valid IPv4 or IPv6 address (e.g., 192.0.2.1)",
                                      "Gib eine gültige IPv4- oder IPv6-Adresse ein, zum Beispiel 192.0.2.1.",
                                  )}
                        </div>
                    {/if}

                    <small class="text-muted">
                        <i class="bi bi-info-circle me-1"></i>
                        {$t(
                            "Enter an IPv4 address (e.g., 192.0.2.1) or IPv6 address (e.g., 2001:db8::1)",
                            "Gib eine IPv4-Adresse (z. B. 192.0.2.1) oder IPv6-Adresse (z. B. 2001:db8::1) ein.",
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
                                {#each $appConfig.rbls as rbl}
                                    <li class="mb-2">
                                        <i class="bi bi-arrow-right me-2"></i>{rbl}
                                    </li>
                                {/each}
                            </ul>
                        </div>
                    </div>
                </div>

                <div class="col-md-6">
                    <div class="card h-100 border-0 bg-light">
                        <div class="card-body">
                            <h3 class="h6 mb-3">
                                <i class="bi bi-info-circle-fill text-primary me-2"></i>
                                {$t("Why Check Blacklists?", "Warum sind Sperrlisten wichtig?")}
                            </h3>
                            <p class="small mb-2">
                                {$t(
                                    "DNS-based blacklists (RBLs) are used by email servers to identify and block spam sources. Being listed can severely impact email deliverability.",
                                    "Mailserver nutzen DNS-Sperrlisten (RBLs), um Spamquellen zu erkennen und zu blockieren. Ein Eintrag kann die Zustellung erschweren.",
                                )}
                            </p>
                            <p class="small mb-3">
                                {$t(
                                    "This tool checks your IP against multiple popular RBLs to help you:",
                                    "Der Abgleich mit bekannten DNS-Sperrlisten hilft dir dabei,",
                                )}
                            </p>
                            <ul class="list-unstyled mb-3 small">
                                <li class="mb-1">
                                    <i class="bi bi-arrow-right me-2"></i>{$t(
                                        "Monitor IP reputation",
                                        "den Ruf der IP-Adresse zu beobachten",
                                    )}
                                </li>
                                <li class="mb-1">
                                    <i class="bi bi-arrow-right me-2"></i>{$t(
                                        "Identify deliverability issues",
                                        "Zustellprobleme zu erkennen",
                                    )}
                                </li>
                                <li class="mb-1">
                                    <i class="bi bi-arrow-right me-2"></i>{$t(
                                        "Take corrective action",
                                        "Probleme gezielt zu beheben",
                                    )}
                                </li>
                            </ul>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Additional Info -->
            <div class="alert alert-info border-0">
                <h3 class="h6 mb-2">
                    <i class="bi bi-lightbulb me-2"></i>
                    {$t("Need Complete Email Analysis?", "Möchtest du die gesamte E-Mail prüfen?")}
                </h3>
                <p class="small mb-2">
                    {$t(
                        "For comprehensive deliverability testing including DKIM verification, content analysis, spam scoring, and more:",
                        "Der E-Mail-Test prüft zusätzlich DKIM, Inhalt und Spam-Wertung.",
                    )}
                </p>
                <a href="/" class="btn btn-sm btn-outline-primary">
                    <i class="bi bi-envelope-plus me-1"></i>
                    {$t("Send Test Email", "Testmail senden")}
                </a>
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
