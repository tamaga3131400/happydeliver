<script lang="ts">
    import { t } from "$lib/stores/language";
    import { createEventDispatcher } from "svelte";

    import type { Test } from "$lib/api/types.gen";
    import EmailAddressDisplay from "./EmailAddressDisplay.svelte";

    const dispatch = createEventDispatcher();

    interface Props {
        test: Test;
        nbfetch: number;
        nextfetch: number;
        fetching?: boolean;
    }

    let { test, nbfetch, nextfetch, fetching = false }: Props = $props();

    let lastForcedCheck = $state(Date.now() - 12345);
    function forceCheck() {
        lastForcedCheck = Date.now();
        dispatch("force-inbox-check");
    }
</script>

<div class="row justify-content-center">
    <div class="col-lg-8 fade-in">
        <div class="card shadow-lg">
            <div class="card-body p-3 p-sm-5 text-center">
                <div class="pulse mb-4">
                    <i class="bi bi-envelope-paper display-1 text-primary"></i>
                </div>

                <h2 class="fw-bold mb-3">
                    {$t("Waiting for Your Email", "Warten auf deine Testmail")}
                </h2>
                <p class="text-muted mb-4">
                    {$t(
                        "Send your test email to the address below:",
                        "Sende deine Testmail an diese Adresse.",
                    )}
                </p>

                <div class="mb-4">
                    <EmailAddressDisplay email={test.email} />
                </div>

                <div class="alert alert-info mb-4" role="alert">
                    <i class="bi bi-lightbulb me-2"></i>
                    {#if nbfetch > 4}
                        <strong>{$t("Tip", "Tipp")}</strong>
                        {$t(
                            "Check whether the message is still in your outbox.",
                            "Prüfe, ob die Nachricht noch im Postausgang liegt.",
                        )}
                    {:else}
                        <strong>{$t("Tip", "Tipp")}</strong>
                        {$t(
                            "For accurate results, send a message similar to the emails you normally send.",
                            "Für aussagekräftige Ergebnisse sende eine Nachricht, die deinen üblichen E-Mails ähnelt.",
                        )}
                    {/if}
                </div>

                <div class="d-flex align-items-center justify-content-center gap-2 text-muted">
                    <div class="spinner-border spinner-border-sm" role="status"></div>
                    {#if fetching || nextfetch === 0}
                        <small>{$t("Looking for new email...", "Posteingang wird geprüft …")}</small
                        >
                    {:else if nextfetch}
                        <div>
                            <small>
                                {$t(
                                    `Next inbox check in ${nextfetch} ${nextfetch === 1 ? "second" : "seconds"} …`,
                                    `Nächste Prüfung in ${nextfetch} ${nextfetch === 1 ? "Sekunde" : "Sekunden"} …`,
                                )}
                            </small>
                            {#if nbfetch > 0}
                                <button
                                    type="button"
                                    class="btn btn-sm btn-link"
                                    onclick={forceCheck}
                                    disabled={nbfetch + Date.now() < lastForcedCheck + 10000}
                                >
                                    <i class="bi bi-mailbox me-1"></i>{$t(
                                        "Check now",
                                        "Jetzt prüfen",
                                    )}
                                </button>
                            {/if}
                        </div>
                    {:else}
                        <small
                            >{$t(
                                "Checking for email every 3 seconds...",
                                "Der Posteingang wird alle drei Sekunden geprüft …",
                            )}</small
                        >
                    {/if}
                </div>
            </div>
        </div>

        <!-- Instructions Card -->
        <div class="card mt-4">
            <div class="card-body">
                <h5 class="fw-bold mb-3">
                    <i class="bi bi-info-circle me-2"></i>{$t(
                        "What we'll check:",
                        "Das wird geprüft",
                    )}
                </h5>
                <div class="row">
                    <div class="col-md-6">
                        <ul class="list-unstyled mb-0">
                            <li class="mb-2">
                                <i class="bi bi-check2 text-success me-2"></i> SPF, DKIM, DMARC, BIMI
                            </li>
                            <li class="mb-2">
                                <i class="bi bi-check2 text-success me-2"></i>
                                {$t("DNS Records", "DNS-Einträge")}
                            </li>
                            <li class="mb-2">
                                <i class="bi bi-check2 text-success me-2"></i>
                                {$t("SpamAssassin Score", "SpamAssassin-Bewertung")}
                            </li>
                        </ul>
                    </div>
                    <div class="col-md-6">
                        <ul class="list-unstyled mb-0">
                            <li class="mb-2">
                                <i class="bi bi-check2 text-success me-2"></i>
                                {$t("Blacklist Status", "Sperrlisteneinträge")}
                            </li>
                            <li class="mb-2">
                                <i class="bi bi-check2 text-success me-2"></i>
                                {$t("Content Quality", "Inhaltsqualität")}
                            </li>
                            <li class="mb-2">
                                <i class="bi bi-check2 text-success me-2"></i>
                                {$t("Header Validation", "Prüfung der Kopfzeilen")}
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<style>
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

    .pulse {
        animation: pulse 2s ease-in-out infinite;
    }

    @keyframes pulse {
        0%,
        100% {
            opacity: 1;
        }
        50% {
            opacity: 0.5;
        }
    }
</style>
