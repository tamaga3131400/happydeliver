<script lang="ts">
    import "bootstrap-icons/font/bootstrap-icons.css";
    import "bootstrap/dist/css/bootstrap.min.css";
    import "../app.css";

    import Logo from "$lib/components/Logo.svelte";
    import { appConfig } from "$lib/stores/config";
    import { language, t } from "$lib/stores/language";
    import { theme } from "$lib/stores/theme";
    import { onMount } from "svelte";

    interface Props {
        children?: import("svelte").Snippet;
    }

    let { children }: Props = $props();

    onMount(() => {
        document.documentElement.setAttribute("data-bs-theme", $theme);
    });

    function toggleTheme() {
        $theme = $theme === "light" ? "dark" : "light";
    }
</script>

<svelte:head>
    <link rel="icon" href="/img/zenmail-plane.svg" type="image/svg+xml" />
</svelte:head>

<div class="min-vh-100 d-flex flex-column">
    <nav class="navbar navbar-expand-lg navbar-light shadow-sm">
        <div class="container">
            <a class="navbar-brand fw-bold d-inline-flex align-items-center gap-2" href="/">
                <img
                    class="brand-mark"
                    src={$appConfig.custom_logo_url || "/img/zenmail-plane.svg"}
                    alt=""
                    referrerpolicy="no-referrer"
                    width="30"
                    height="30"
                />
                Deliver Zenmail
            </a>
            <div class="d-flex align-items-center">
                <label for="site-language" class="visually-hidden"
                    >{$t("Language", "Sprache")}</label
                >
                <select
                    id="site-language"
                    class="form-select form-select-sm w-auto"
                    bind:value={$language}
                >
                    <option lang="de" value="de">Deutsch</option>
                    <option lang="en" value="en">English</option>
                </select>
                <button
                    class="btn btn-link ms-auto {$theme == 'light' ? 'text-dark' : 'text-light'}"
                    onclick={toggleTheme}
                    aria-label={$t("Toggle color mode", "Farbschema wechseln")}
                    title={$t("Toggle color mode", "Farbschema wechseln")}
                >
                    <i class="bi bi-{$theme === 'light' ? 'moon-stars-fill' : 'sun-fill'}"></i>
                </button>
            </div>
        </div>
    </nav>

    <main class="flex-grow-1">
        {@render children?.()}
    </main>

    <footer
        id="footer-classic"
        class="px-4 px-md-5 py-2 bg-tertiary d-flex flex-wrap gap-2 justify-content-between"
    >
        <a href="https://github.com/tamaga3131400/happydeliver"
            >{$t("Based on happyDeliver", "Basiert auf happyDeliver")}</a
        >
        <ul class="d-flex footer-nav">
            <li><a href="/tools/">Tools</a></li>
            <li>
                <a
                    href="https://github.com/tamaga3131400/happydeliver/blob/deliver-zenmail/api/openapi.yaml"
                    target="_blank"
                >
                    API
                </a>
            </li>
            <li>
                <a href="https://github.com/tamaga3131400/happydeliver/tree/deliver-zenmail-admin">
                    {$t("Source code (AGPL v3)", "Quellcode (AGPL v3)")}
                </a>
            </li>
            {#if $appConfig.admin_enabled}
                <li>
                    <a href="/admin" data-sveltekit-reload
                        >{$t("Administration", "Administration")}</a
                    >
                </li>
            {/if}
            <li><a href="https://github.com/tamaga3131400/happydeliver/issues" target="_blank">Feedback</a></li>
        </ul>
    </footer>

    <footer id="footer-happydomain" class="d-none pt-3 pb-2 bg-dark text-light">
        <div class="container mb-4">
            <div class="row row-cols-1 row-cols-md-2 row-cols-lg-4">
                <div class="col">
                    <h3>
                        <Logo color="white" />
                    </h3>
                    <ul class="footer-links">
                        <li><a href="/#features">Features</a></li>
                        <li>
                            <a
                                href="https://github.com/tamaga3131400/happydeliver/releases"
                                target="_blank">Download</a
                            >
                        </li>
                        <li>
                            <a href="https://github.com/tamaga3131400/happydeliver" target="_blank">
                                GitHub
                            </a>
                        </li>
                    </ul>
                </div>
                <div class="col">
                    <h3>Our association</h3>
                    <ul class="footer-links">
                        <li>
                            <a href="https://github.com/tamaga3131400/happydeliver" target="_blank">
                                About us
                            </a>
                        </li>
                        <li>
                            <a href="https://github.com/tamaga3131400/happydeliver/issues" target="_blank">
                                Contact
                            </a>
                        </li>
                        <li>
                            <a href="https://github.com/tamaga3131400/happydeliver" target="_blank">
                                Legal notice
                            </a>
                        </li>
                    </ul>
                </div>
                <div class="col"></div>
                <div class="col">
                    <h3>Follow-us</h3>
                    <div
                        class="d-flex flex-wrap justify-content-between footer-links"
                        style="gap: .5em; font-size: 2em"
                    >
                        <a
                            href="https://github.com/tamaga3131400/happydeliver"
                            target="_blank"
                            aria-label="Visit our GitHub repository"
                        >
                            <i class="bi bi-github"></i>
                        </a>
                        <a
                            href="https://github.com/tamaga3131400/happydeliver/issues"
                            target="_blank"
                            aria-label="Share your feedback"
                        >
                            <i class="bi bi-lightbulb-fill"></i>
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </footer>
</div>

<style>
    .brand-mark {
        object-fit: contain;
    }

    footer {
        border-top: 3px solid #0f625e;
    }

    footer a {
        text-decoration: none;
    }

    .footer-nav {
        list-style: none;
        padding: 0;
        margin: 0;
        gap: 0;
        flex-wrap: wrap;
    }

    .footer-nav li {
        display: flex;
        align-items: center;
    }

    .footer-nav li:not(:last-child)::after {
        content: "|";
        margin: 0 0.5rem;
    }

    .footer-links {
        list-style: none;
        padding: 0;
    }

    .footer-links li {
        margin-bottom: 12px;
    }

    .footer-links a {
        color: rgba(255, 255, 255, 0.7);
        transition: color 0.3s;
    }

    .footer-links a:hover {
        color: white;
    }
</style>
