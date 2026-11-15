<script lang="ts">
    import { goto } from "$app/navigation";

    import { createTest as apiCreateTest } from "$lib/api";
    import { FeatureCard, HowItWorksStep } from "$lib/components";
    import { language, t } from "$lib/stores/language";
    import { appConfig } from "$lib/stores/config";

    let loading = $state(false);
    let error = $state(false);

    async function createTest() {
        loading = true;
        error = false;

        try {
            const response = await apiCreateTest();
            if (response.data) {
                await goto(`/test/${response.data.id}`);
            } else {
                error = true;
            }
        } catch (err) {
            console.error(err);
            error = true;
        } finally {
            loading = false;
        }
    }

    function getRetentionTimeText(): string {
        if (!$appConfig.report_retention) return $t("indefinitely", "unbefristet");

        const hours = Math.floor($appConfig.report_retention / 3_600_000_000_000);
        const exact = (divisor: number) => hours >= divisor && hours % divisor === 0;
        const unit = exact(720) ? "month" : exact(168) ? "week" : exact(24) ? "day" : "hour";
        const divisor = { month: 720, week: 168, day: 24, hour: 1 }[unit];
        return new Intl.NumberFormat($language, {
            style: "unit",
            unit,
            unitDisplay: "long",
        }).format(Math.floor(hours / divisor));
    }

    const features = $derived([
        {
            icon: "bi-shield-check",
            title: $t("Authentication", "Authentifizierung"),
            description: $t(
                "SPF, DKIM, DMARC, and BIMI validation with detailed results and recommendations.",
                "Prüft SPF, DKIM, DMARC und BIMI und zeigt Ergebnisse und Empfehlungen.",
            ),
            variant: "primary" as const,
        },
        {
            icon: "bi-building-check",
            title: $t("BIMI Support", "BIMI-Unterstützung"),
            description: $t(
                "Brand Indicators for Message Identification - verify your brand logo configuration.",
                "Überprüft die Konfiguration des Logos, das bei Empfängern angezeigt werden kann.",
            ),
            variant: "info" as const,
        },
        {
            icon: "bi-link-45deg",
            title: $t("ARC Verification", "ARC-Prüfung"),
            description: $t(
                "Authenticated Received Chain validation for forwarded emails and mailing lists.",
                "Prüft die Authentifizierungskette bei Weiterleitungen und Mailinglisten.",
            ),
            variant: "primary" as const,
        },
        {
            icon: "bi-check2-circle",
            title: $t("Domain Alignment", "Domain-Übereinstimmung"),
            description: $t(
                "Verify alignment between From, Return-Path, and DKIM domains for DMARC compliance.",
                "Prüft für DMARC, ob die Absenderdomain mit der SPF- oder DKIM-Domain übereinstimmt.",
            ),
            variant: "success" as const,
        },
        {
            icon: "bi-globe",
            title: $t("DNS Records", "DNS-Einträge"),
            description: $t(
                "Verify PTR, MX, SPF, DKIM, DMARC, and BIMI records are properly configured.",
                "Prüft die DNS-Einträge für PTR, MX, SPF, DKIM, DMARC und BIMI.",
            ),
            variant: "success" as const,
        },
        {
            icon: "bi-bug",
            title: $t("Spam Score", "Spam-Bewertung"),
            description: $t(
                "SpamAssassin analysis with detailed test results and scoring.",
                "Analysiert die Nachricht mit SpamAssassin und zeigt die Ergebnisse im Detail.",
            ),
            variant: "warning" as const,
        },
        {
            icon: "bi-list-check",
            title: $t("Blacklists", "Sperrlisten"),
            description: $t(
                "Check if your IP is listed in major DNS-based blacklists (RBLs).",
                "Prüft, ob deine IP-Adresse auf bekannten DNS-Sperrlisten (RBLs) steht.",
            ),
            variant: "danger" as const,
        },
        {
            icon: "bi-card-heading",
            title: $t("Header Quality", "E-Mail-Kopfzeilen"),
            description: $t(
                "Validate required headers, check for missing fields and alignment.",
                "Prüft Pflichtfelder und die Übereinstimmung der Angaben in den Kopfzeilen.",
            ),
            variant: "secondary" as const,
        },
        {
            icon: "bi-file-text",
            title: $t("Content Analysis", "Inhaltsanalyse"),
            description: $t(
                "HTML structure, link validation, image analysis, and more.",
                "Prüft HTML-Aufbau, Links und Bilder deiner E-Mail.",
            ),
            variant: "info" as const,
        },
        {
            icon: "bi-bar-chart",
            title: $t("Detailed Scoring", "Detaillierte Bewertung"),
            description: $t(
                "A to F deliverability grade with breakdown by category and recommendations.",
                "Bewertet die Zustellbarkeit von A bis F und gibt Empfehlungen je Kategorie.",
            ),
            variant: "primary" as const,
        },
        {
            icon: "bi-lock",
            title: $t("Privacy First", "Datenschutz"),
            description: $t(
                `Reports are stored on this server for: ${getRetentionTimeText()}. Server logs are deleted after 10 days at most.`,
                `Speicherdauer der Berichte auf diesem Server: ${getRetentionTimeText()}. Server-Protokolle werden nach höchstens 10 Tagen gelöscht.`,
            ),
            variant: "success" as const,
        },
    ]);

    const steps = $derived([
        {
            step: 1,
            title: $t("Create Test", "Test erstellen"),
            description: $t(
                "Click the button to generate a unique test email address.",
                "Erstelle eine eindeutige E-Mail-Adresse für deinen Test.",
            ),
        },
        {
            step: 2,
            title: $t("Send Email", "E-Mail senden"),
            description: $t(
                "Send a test email from your mail server to the provided address.",
                "Sende eine Testmail über deinen Mailserver an diese Adresse.",
            ),
        },
        {
            step: 3,
            title: $t("View Results", "Ergebnisse ansehen"),
            description: $t(
                "Get instant detailed analysis with actionable recommendations.",
                "Öffne den Bericht mit konkreten Empfehlungen.",
            ),
        },
    ]);
</script>

<svelte:head>
    <title>Deliver Zenmail · {$t("Email Deliverability Test", "E-Mail-Zustelltest")}</title>
</svelte:head>

<!-- Hero Section -->
<section class="hero py-5" id="hero">
    <div class="container py-5">
        <div class="row align-items-center">
            <div class="col-lg-8 mx-auto text-center fade-in">
                <h1 class="display-3 fw-bold mb-4">
                    {$t("Test Your Email Deliverability", "Zustellbarkeit von E-Mails prüfen")}
                </h1>
                <p class="lead mb-4 opacity-90">
                    {$t(
                        "Get detailed insights into your email configuration, authentication, spam score, and more. Open-source, self-hosted, and privacy-focused.",
                        "Prüfe die Authentifizierung und den Spam-Wert deiner E-Mails. Der Bericht zeigt, was du an deiner Mailkonfiguration verbessern kannst.",
                    )}
                </p>
                <button
                    class="btn btn-lg px-4 px-sm-5 py-3 shadow cta-button"
                    onclick={createTest}
                    disabled={loading}
                >
                    {#if loading}
                        <span class="spinner-border spinner-border-sm me-2" role="status"></span>
                        {$t("Creating Test...", "Test wird erstellt …")}
                    {:else}
                        <i class="bi bi-envelope-plus me-2"></i>
                        {$t("Start Free Test", "Kostenlosen Test starten")}
                    {/if}
                </button>

                {#if error}
                    <div class="alert alert-danger mt-4 d-inline-block" role="alert">
                        <i class="bi bi-exclamation-triangle me-2"></i>
                        {$t(
                            "Could not create the test. Please try again.",
                            "Der Test konnte nicht erstellt werden. Bitte versuche es erneut.",
                        )}
                    </div>
                {/if}
            </div>
        </div>
    </div>
</section>

<!-- Features Section -->
<section class="py-5" id="features">
    <div class="container py-4">
        <div class="row text-center mb-5">
            <div class="col-lg-8 mx-auto">
                <h2 class="display-5 fw-bold mb-3">
                    {$t("Comprehensive Email Analysis", "E-Mails im Detail analysieren")}
                </h2>
                <p class="text-muted">
                    {$t(
                        "Your favorite deliverability tester, open-source and self-hostable for complete privacy and control.",
                        "Prüfe, welche Einstellungen deinem Mailserver bei der Zustellung helfen und welche Probleme verursachen können.",
                    )}
                </p>
            </div>
        </div>

        <div class="row g-4 justify-content-center">
            {#each features as feature}
                <div class="col-md-6 col-lg-3">
                    <FeatureCard {...feature} />
                </div>
            {/each}
        </div>
    </div>
</section>

<!-- {$t("How It Works", "So funktioniert der Test")} -->
<section class="bg-light py-5" id="steps">
    <div class="container py-4">
        <div class="row text-center mb-5">
            <div class="col-lg-8 mx-auto">
                <h2 class="display-5 fw-bold mb-3">
                    {$t("How It Works", "So funktioniert der Test")}
                </h2>
                <p class="text-muted">
                    {$t(
                        "Simple three-step process to test your email deliverability",
                        "In drei Schritten zum Zustellbericht",
                    )}
                </p>
            </div>
        </div>

        <div class="row g-4">
            {#each steps as stepData}
                <div class="col-md-4">
                    <HowItWorksStep {...stepData} />
                </div>
            {/each}
        </div>

        <div class="text-center mt-5">
            <button
                class="btn btn-primary btn-lg px-4 px-sm-5 py-3"
                onclick={createTest}
                disabled={loading}
            >
                {#if loading}
                    <span class="spinner-border spinner-border-sm me-2" role="status"></span>
                    {$t("Creating Test...", "Test wird erstellt …")}
                {:else}
                    <i class="bi bi-rocket-takeoff me-2"></i>
                    {$t("Get Started Now", "Jetzt starten")}
                {/if}
            </button>
        </div>

        <div class="d-flex flex-wrap justify-content-center gap-2 mt-4">
            <a href="/domain" class="btn btn-secondary btn-lg">
                <i class="bi bi-globe me-2"></i>
                {$t("Test Domain Only", "Nur Domain prüfen")}
            </a>
            <a href="/blacklist" class="btn btn-secondary btn-lg">
                <i class="bi bi-shield-exclamation me-2"></i>
                {$t("Check IP Blacklist", "IP auf Sperrlisten prüfen")}
            </a>
        </div>
    </div>
</section>

<style>
    .hero {
        background:
            radial-gradient(ellipse at 84% 8%, #237068 0%, transparent 54%),
            linear-gradient(125deg, #12313c, #164e50 58%, #1a6058);
        color: #f6fcfa;
    }

    :global([data-bs-theme="dark"]) .hero {
        background:
            radial-gradient(ellipse at 84% 8%, #174c48 0%, transparent 54%),
            linear-gradient(125deg, #102631, #123b3d 58%, #154740);
    }

    .hero h1 {
        text-wrap: balance;
    }

    .hero .lead {
        max-width: 36rem;
        margin-inline: auto;
        color: #d8ece8;
    }

    /* Dark mode section background */
    :global([data-bs-theme="dark"]) #steps {
        background-color: var(--bs-secondary-bg) !important;
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

    .cta-button {
        --bs-btn-color: #203137;
        --bs-btn-bg: #f4ca79;
        --bs-btn-border-color: #f4ca79;
        --bs-btn-hover-color: #152c32;
        --bs-btn-hover-bg: #ffe0a1;
        --bs-btn-hover-border-color: #ffe0a1;
        --bs-btn-focus-shadow-rgb: 244, 202, 121;
        --bs-btn-active-color: #203137;
        --bs-btn-active-bg: #e5b662;
        --bs-btn-active-border-color: #e5b662;
        --bs-btn-disabled-color: #203137;
        --bs-btn-disabled-bg: #f4ca79;
        --bs-btn-disabled-border-color: #f4ca79;
    }

    @media (prefers-reduced-motion: reduce) {
        .fade-in {
            animation: none;
        }
    }
</style>
