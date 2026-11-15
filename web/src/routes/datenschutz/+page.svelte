<script lang="ts">
    import OperatorAddress from "$lib/components/OperatorAddress.svelte";
    import { appConfig } from "$lib/stores/config";
    import { language } from "$lib/stores/language";

    // report_retention is a Go duration in nanoseconds.
    let retentionDays = $derived(
        Math.max(1, Math.round(($appConfig.report_retention ?? 864e12) / 864e11)),
    );
</script>

<svelte:head>
    <title>Datenschutz · Deliver Zenmail</title>
</svelte:head>

<div class="container py-5" lang="de">
    <div class="legal mx-auto">
        <p class="text-uppercase text-muted small fw-semibold mb-1">Rechtliches</p>
        <h1 class="fw-bold mb-4">Datenschutzerklärung</h1>
        {#if $language !== "de"}
            <p class="text-muted small" lang="en">This page is available in German only.</p>
        {/if}

        <h2>Verantwortlicher</h2>
        <OperatorAddress />

        <h2>Kurz gesagt</h2>
        <p>
            Diese Website setzt keine Cookies, nutzt kein Tracking und keine Analysedienste und lädt
            keine Inhalte von fremden Servern (keine externen Schriften oder Skripte). Für die
            Nutzung ist keine Anmeldung nötig. Testmails und Berichte werden nach spätestens {retentionDays}
            {retentionDays === 1 ? "Tag" : "Tagen"} automatisch gelöscht.
        </p>

        {#if $appConfig.operator?.hosting}
            <h2>Hosting</h2>
            <p>Die Website liegt auf einem Server der {$appConfig.operator.hosting}.</p>
        {/if}

        <h2>Server-Logdateien</h2>
        <p>Bei jedem Aufruf speichert der Webserver automatisch:</p>
        <ul>
            <li>IP-Adresse</li>
            <li>Datum und Uhrzeit</li>
            <li>
                aufgerufene Adresse, bei den Prüf-Tools einschließlich der eingegebenen Domain oder
                IP-Adresse
            </li>
            <li>HTTP-Statuscode und übertragene Datenmenge</li>
            <li>zuvor besuchte Seite (Referrer), falls dein Browser sie übermittelt</li>
            <li>Browserkennung (User-Agent)</li>
        </ul>
        <p>Bei Fehlern wird zusätzlich ein Fehlereintrag mit diesen Angaben gespeichert.</p>
        <p>
            Zweck ist die Auslieferung der Website, die Sicherheit des Servers (zum Beispiel das
            Erkennen von Angriffen) und die Fehleranalyse. Rechtsgrundlage ist Art. 6 Abs. 1 lit. f
            DSGVO; das berechtigte Interesse liegt im sicheren und stabilen Betrieb.
        </p>
        <p>
            Die Logdateien werden täglich rotiert und spätestens nach 10 Tagen gelöscht. Sie werden
            nicht zu anderen Zwecken ausgewertet und nicht mit anderen Daten zusammengeführt. Zur
            Begrenzung der Anfragen wird die IP-Adresse außerdem kurzzeitig im Arbeitsspeicher
            gehalten.
        </p>

        <h2>E-Mail-Test</h2>
        <p>
            Wenn du eine Testmail an die angezeigte Adresse schickst, speichert der Server die
            vollständige Nachricht (Kopfzeilen, Inhalt und Anhänge) sowie den daraus erstellten
            Bericht. Darin enthalten sind unter anderem Absender- und Empfängeradressen sowie
            IP-Adresse und Name des sendenden Mailservers.
        </p>
        <p>
            Zweck ist die Erstellung des von dir angeforderten Berichts. Rechtsgrundlage ist Art. 6
            Abs. 1 lit. b DSGVO. Nachricht und Bericht werden nach spätestens {retentionDays}
            {retentionDays === 1 ? "Tag" : "Tagen"} automatisch gelöscht.
        </p>
        <p>
            Für die Prüfung werden IP-Adressen, Domains und Links aus der Nachricht per DNS bei
            öffentlichen Sperrlisten (DNSBL) abgefragt, und der Spamfilter rspamd übermittelt
            Prüfsummen (Hashes) von Textteilen an den Abgleichdienst des rspamd-Projekts. Der Inhalt
            der Nachricht selbst wird nicht weitergegeben.
        </p>
        <p>
            Der Bericht ist über seinen Link abrufbar. Wer den Link kennt, kann ihn ansehen. Schicke
            deshalb keine vertraulichen Inhalte, sondern eine typische Mail ohne persönliche Daten.
        </p>

        <h2>Prüf-Tools und Sicherheitslage</h2>
        <p>
            Was du in die Prüf-Tools eingibst (etwa eine Domain, eine IP-Adresse oder eine
            E-Mail-Adresse), verarbeitet der Server nur, um das Ergebnis zu erstellen. Dafür fragt
            er je nach Tool öffentliche DNS-Resolver (zum Beispiel Google, Cloudflare, Quad9),
            Zertifikats-Logs (crt.sh, CertSpotter), RDAP- und Whois-Server der Registrierungsstellen
            oder das eingegebene Ziel direkt ab. Die Ergebnisse werden nicht gespeichert.
        </p>
        <p>
            Die Entwickler-Tools laufen vollständig in deinem Browser; dabei wird nichts an den
            Server übertragen. Die Sicherheitslage verarbeitet keine personenbezogenen Daten.
        </p>

        <h2>Speicherung im Browser</h2>
        <p>
            Deine Auswahl von Sprache und Farbschema wird im lokalen Speicher deines Browsers
            (localStorage) abgelegt und nicht an den Server übertragen. Diese Speicherung ist für
            die von dir gewählte Funktion unbedingt erforderlich (§ 25 Abs. 2 Nr. 2 TDDDG). Du
            kannst sie jederzeit in deinem Browser löschen.
        </p>

        <h2>Verschlüsselung</h2>
        <p>
            Die Verbindung zu dieser Website ist per TLS (HTTPS) verschlüsselt. Testmails werden
            verschlüsselt angenommen, sofern der sendende Mailserver das unterstützt.
        </p>

        <h2>Rechte nach der DSGVO</h2>
        <p>
            Soweit die jeweiligen Voraussetzungen vorliegen, bestehen die Rechte auf Auskunft (Art.
            15 DSGVO), Berichtigung (Art. 16), Löschung (Art. 17) und Einschränkung der Verarbeitung
            (Art. 18) sowie ein Beschwerderecht bei einer Datenschutz-Aufsichtsbehörde (Art. 77).
            Die Logdaten lassen sich in der Regel keiner bestimmten Person zuordnen (Art. 11 DSGVO).
        </p>
        <p>
            Widerspruchsrecht (Art. 21 DSGVO): Einer Verarbeitung, die auf Art. 6 Abs. 1 lit. f
            DSGVO beruht, kann aus Gründen, die sich aus der besonderen Situation der betroffenen
            Person ergeben, widersprochen werden.
        </p>

        <p class="text-muted mt-4">Stand: November 2026</p>
    </div>
</div>

<style>
    .legal {
        max-width: 46rem;
    }

    h2 {
        font-size: 1.15rem;
        font-weight: 700;
        margin-top: 2rem;
    }
</style>
