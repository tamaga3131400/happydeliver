<script lang="ts">
    import type { AuthenticationResults, DnsResults, HeaderAnalysis } from "$lib/api/types.gen";
    import { t } from "$lib/stores/language";

    interface Props {
        authentication?: AuthenticationResults;
        dns?: DnsResults;
        headers?: HeaderAnalysis;
        rawHeaders?: string;
    }

    let { authentication, dns, headers, rawHeaders }: Props = $props();

    const positiveDKIM = $derived(
        authentication?.dkim?.some((item) => item.result === "pass") ?? false,
    );
    const hasSignature = $derived(
        rawHeaders ? /^dkim-signature\s*:/im.test(rawHeaders) : undefined,
    );
    const firstDKIM = $derived(authentication?.dkim?.find((item) => item.domain && item.selector));
    const signature = $derived(
        rawHeaders?.match(/^dkim-signature:[^\r\n]*(?:\r?\n[ 	]+[^\r\n]*)*/im)?.[0],
    );
    const signingDomain = $derived(
        firstDKIM?.domain || signature?.match(/;\s*d\s*=\s*([a-z0-9.-]+)/i)?.[1],
    );
    const selector = $derived(
        firstDKIM?.selector || signature?.match(/;\s*s\s*=\s*([a-z0-9_.-]+)/i)?.[1],
    );
    const dkimName = $derived(
        selector && signingDomain ? `${selector}._domainkey.${signingDomain}` : undefined,
    );
    const spfDomain = $derived(dns?.rp_domain || authentication?.spf?.domain);
    const spfRecord = $derived(
        dns?.spf_records?.find(
            (item) =>
                item.record &&
                (spfDomain
                    ? item.domain?.toLowerCase() === spfDomain.toLowerCase()
                    : item.domain === dns?.from_domain),
        ),
    );
    const spfPassed = $derived(authentication?.spf?.result === "pass");
    const dkimRecord = $derived(
        dns?.dkim_records?.find(
            (item) => item.domain === signingDomain && item.selector === selector,
        ),
    );
    const domain = $derived(dns?.from_domain || headers?.domain_alignment?.from_domain);
    const orgDomain = $derived(headers?.domain_alignment?.from_org_domain);
    const from = $derived(headers?.headers?.from?.value);
    const dmarc = $derived(dns?.dmarc_record);
    const dmarcPassed = $derived(
        authentication?.dmarc?.result === "pass" ||
            authentication?.dmarc?.result === "domain_pass" ||
            authentication?.dmarc?.result === "orgdomain_pass",
    );
    const dmarcMissing = $derived(
        !dmarc?.record && /no dmarc record found|no such host/i.test(dmarc?.error ?? ""),
    );
    const showDMARC = $derived(!dmarcPassed || Boolean(dmarc?.record && !dmarc.valid));
</script>

<aside
    class="guidance p-3 p-md-4 m-3 rounded"
    aria-label={$t("Configuration guidance", "Hinweise zur Konfiguration")}
>
    <h5 class="h6 fw-bold mb-3">
        {$t("DNS settings for this test", "DNS-Einstellungen für diesen Test")}
    </h5>
    {#if from}
        <p class="small">
            {$t("Tested From address", "Geprüfter Absender")} <strong>{from}</strong>
        </p>
    {:else if domain}
        <p class="small">
            {$t("Tested sender domain", "Geprüfte Absenderdomain")} <strong>{domain}</strong>
        </p>
    {/if}
    {#if !spfPassed}
        <div class="mb-3">
            <h6 class="fw-bold">SPF</h6>
            <p class="mb-0">
                {$t(
                    "The receiving server did not report SPF pass. Verify the envelope sender domain (MAIL FROM) with your sending provider. For an empty envelope sender, SPF uses the sending host’s HELO name.",
                    "Der empfangende Server meldet kein erfolgreiches SPF. Prüfe beim Versanddienst die technische Absenderdomain (MAIL FROM). Bei leerem MAIL FROM verwendet SPF den HELO-Namen des Versandservers.",
                )}
            </p>
        </div>
    {/if}

    {#if !positiveDKIM}
        <div class="mb-3">
            <h6 class="fw-bold">DKIM</h6>
            {#if hasSignature === false}
                <p class="mb-2">
                    {$t(
                        "This email had no DKIM-Signature header. Enable DKIM signing for the From domain in the mail server or provider that actually sent the message.",
                        "Diese E-Mail enthält keine DKIM-Signatur. Aktiviere die DKIM-Signierung für die Absenderdomain bei dem Mailserver oder Anbieter, über den du die Nachricht verschickt hast.",
                    )}
                </p>
                <p class="mb-0">
                    {$t(
                        "Publish the DNS entry supplied by that provider using its selector. A DNS record alone does not sign outgoing mail.",
                        "Übernimm anschließend den DNS-Eintrag mit dem Selektor deines Anbieters. Der DNS-Eintrag allein signiert ausgehende Nachrichten noch nicht.",
                    )}
                </p>
            {:else if dkimName}
                <p class="mb-2">
                    {$t(
                        "The mail or report identifies a signing domain and selector. Check the public key at",
                        "Die Mail oder der Bericht nennt eine Signatur-Domain und einen Selektor. Prüfe den öffentlichen Schlüssel unter",
                    )} <code>{dkimName}</code>.
                </p>
                {#if dkimRecord?.error}<p class="small mb-2">{dkimRecord.error}</p>{/if}
                <p class="mb-0">
                    {$t(
                        "Compare the DNS entry with your sending provider’s value and check whether a gateway rewrites signed headers or the message body.",
                        "Vergleiche den DNS-Eintrag mit dem Wert des Versanddienstes. Prüfe auch, ob ein Gateway signierte Kopfzeilen oder den Nachrichteninhalt verändert.",
                    )}
                </p>
            {:else}
                <p class="mb-0">
                    {$t(
                        "The receiving server did not report a successful DKIM verification. Check the sending service and whether your receiving mail server records DKIM results in Authentication-Results.",
                        "Der empfangende Server hat keine erfolgreiche DKIM-Prüfung gemeldet. Prüfe den Versanddienst und ob der empfangende Mailserver DKIM-Ergebnisse in Authentication-Results protokolliert.",
                    )}
                </p>
            {/if}
        </div>
    {/if}

    {#if showDMARC}
        <div class="mb-3">
            <h6 class="fw-bold">DMARC</h6>
            {#if domain && dmarcMissing}
                <p class="mb-2">
                    {$t(
                        "No DMARC record was found directly at",
                        "Direkt unter dieser Adresse wurde kein DMARC-Eintrag gefunden",
                    )} <code>_dmarc.{domain}</code>.
                </p>
                {#if orgDomain && orgDomain !== domain}
                    <p class="mb-2">
                        {$t(
                            "Check whether the parent domain already provides a policy before creating an entry.",
                            "Prüfe zuerst, ob die übergeordnete Domain bereits eine Richtlinie vorgibt.",
                        )} <code>_dmarc.{orgDomain}</code>
                    </p>
                {:else}
                    <p class="mb-2">
                        {$t(
                            "For a domain without a DMARC policy, this DNS TXT value is a starting point for monitoring.",
                            "Wenn für die Domain noch keine DMARC-Richtlinie existiert, kannst du mit diesem DNS-TXT-Wert zur Beobachtung beginnen.",
                        )} <code>v=DMARC1; p=none</code>
                    </p>
                {/if}
            {:else if domain && dmarc?.record && !dmarc.valid}
                <p class="mb-2">
                    {$t(
                        "The test found a DMARC record that did not validate at",
                        "Der gefundene DMARC-Eintrag wurde als ungültig erkannt unter",
                    )} <code>_dmarc.{domain}</code>. {$t(
                        "Check its syntax and keep a single DMARC TXT record.",
                        "Prüfe die Syntax und hinterlege genau einen DMARC-TXT-Eintrag.",
                    )}
                </p>
            {:else if domain && dmarc?.valid}
                <p class="mb-2">
                    {$t(
                        "A DMARC record was found. Do not add a second one.",
                        "Ein DMARC-Eintrag wurde gefunden. Lege keinen zweiten Eintrag an.",
                    )}
                </p>
            {:else}
                <p class="mb-2">
                    {$t(
                        "This report does not confirm a DMARC result. Check the DNS lookup and the receiving server’s Authentication-Results before changing a policy.",
                        "Der Bericht bestätigt kein DMARC-Ergebnis. Prüfe die DNS-Abfrage und Authentication-Results am empfangenden Server, bevor du eine Richtlinie änderst.",
                    )}
                </p>
            {/if}
            <p class="mb-0">
                {$t(
                    "DMARC needs a passing SPF or DKIM result whose authenticated domain aligns with the visible From domain.",
                    "Für DMARC muss SPF oder DKIM erfolgreich sein und die dabei authentifizierte Domain mit der sichtbaren Absenderdomain übereinstimmen.",
                )}
            </p>
        </div>
    {/if}
    <details class="mb-3" open={!spfPassed || !positiveDKIM || showDMARC}>
        <summary class="fw-semibold"
            >{$t("DNS records to enter", "DNS-Einträge zum Eintragen")}</summary
        >
        <dl class="small mt-3 mb-0">
            <dt>SPF</dt>
            <dd>
                {$t("Name", "Name")}
                {#if spfDomain}<code>{spfDomain}</code
                    >{#if orgDomain && spfDomain.toLowerCase() === orgDomain.toLowerCase()}{" "}({$t(
                            "zone root, often",
                            "Zonenwurzel, oft",
                        )}
                        <code>@</code>){/if}{:else}{$t(
                        "Envelope sender domain from the provider",
                        "Technische Absenderdomain laut Versanddienst",
                    )}{/if}
                <br />{$t("Type", "Typ")} <code>TXT</code>
                <br />{$t("Value template", "Wert (Vorlage)")}
                <code
                    >v=spf1 include:&lt;{$t(
                        "INCLUDE-FROM-PROVIDER",
                        "INCLUDE-DES-VERSANDDIENSTES",
                    )}&gt; ~all</code
                >
                <br />{$t(
                    "Only your sending provider can supply the include. If a v=spf1 record already exists, add the provider to that record before the final all mechanism. Keep one SPF record per name.",
                    "Den Include kann nur dein Versanddienst nennen. Gibt es bereits einen v=spf1-Eintrag, ergänze den Versanddienst darin vor dem abschließenden all. Pro DNS-Name darf es nur einen SPF-Eintrag geben.",
                )}
                {#if spfRecord?.record}
                    <br />{$t("Value found by this test", "Im Test gefundener Wert")}
                    <code>{spfRecord.record}</code>
                {/if}
            </dd>
            <dt>DKIM</dt>
            <dd>
                {$t("Name", "Name")}
                <code
                    >{dkimName ??
                        (domain
                            ? `SELECTOR._domainkey.${domain}`
                            : "SELECTOR._domainkey.DOMAIN")}</code
                >
                <br />{$t("Type", "Typ")} <code>TXT</code>
                {$t(
                    "(or CNAME if your provider supplies a CNAME target)",
                    "(oder CNAME, wenn der Versanddienst ein CNAME-Ziel vorgibt)",
                )}
                <br />{$t("Value template", "Wert (Vorlage)")}
                <code
                    >v=DKIM1; k=rsa; p=&lt;{$t(
                        "PUBLIC-KEY-FROM-PROVIDER",
                        "ÖFFENTLICHER-SCHLÜSSEL-DES-VERSANDDIENSTES",
                    )}&gt;</code
                >
                <br />{$t(
                    "Only the sending server or service can supply the public key or CNAME target. Replace SELECTOR with the supplied selector if it is not shown above. Keep the private key on the sending server.",
                    "Den öffentlichen Schlüssel oder das CNAME-Ziel kann nur der Versanddienst liefern. Ersetze SELECTOR durch den tatsächlichen Selektor, falls er oben nicht eingesetzt ist. Der private Schlüssel bleibt beim Versanddienst.",
                )}
                {#if dkimRecord?.record}
                    <br />{$t("Value found by this test", "Im Test gefundener Wert")}
                    <code>{dkimRecord.record}</code>
                {/if}
            </dd>
            <dt>DMARC</dt>
            <dd>
                {$t("Name", "Name")} <code>_dmarc.{domain ?? "DOMAIN"}</code>
                <br />{$t("Type", "Typ")} <code>TXT</code>
                <br />{$t("Value template for monitoring", "Wert (Vorlage zum Beobachten)")}
                <code>v=DMARC1; p=none</code>
                <br />{$t(
                    "Edit an existing DMARC record instead of creating a second one. If the From domain is a subdomain, check the inherited policy first.",
                    "Bearbeite einen bestehenden DMARC-Eintrag, statt einen zweiten anzulegen. Bei einer Subdomain prüfe zuerst, ob sie eine übergeordnete Richtlinie erbt.",
                )}
                {#if dmarc?.record}
                    <br />{$t("Value found by this test", "Im Test gefundener Wert")}
                    <code>{dmarc.record}</code>
                {/if}
            </dd>
        </dl>
        <p class="small mb-0">
            {$t(
                "If your DNS editor already adds the zone name, enter only the part before the zone. At the zone root, use @ if your DNS provider uses that notation.",
                "Wenn dein DNS-Editor den Zonennamen automatisch anhängt, gib nur den Teil vor der Zone ein. Für die Zone selbst wird häufig @ verwendet.",
            )}
        </p>
    </details>
    <p class="small mb-0">
        {$t(
            "After making changes, send another test from the same address through the same sending service.",
            "Sende nach der Änderung eine neue Testmail von derselben Adresse und über denselben Versanddienst.",
        )}
    </p>
</aside>

<style>
    .guidance {
        background: var(--bs-tertiary-bg);
        border-inline-start: 3px solid #168278;
        overflow-wrap: anywhere;
    }
</style>
