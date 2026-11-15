import { describe, expect, it } from "vitest";

import { bbcodeToHtml, devTools, encodeEntities, formatJson, parseUrl } from "./devtools";

describe("developer tools", () => {
    it("formats and minifies JSON", () => {
        expect(formatJson('{"a":[1,2]}', { mode: "format", indent: "2" })).toBe('{\n  "a": [\n    1,\n    2\n  ]\n}');
        expect(formatJson('{ "a" : 1 }', { mode: "minify" })).toBe('{"a":1}');
        expect(() => formatJson("{a:1}", { mode: "format", indent: "2" })).toThrow();
    });

    it("converts BBCode without letting markup or unsafe links through", () => {
        expect(bbcodeToHtml("[b]x[/b]")).toBe("<strong>x</strong>");
        expect(bbcodeToHtml("<script>alert(1)</script>")).toBe("&lt;script&gt;alert(1)&lt;/script&gt;");
        expect(bbcodeToHtml("[url=javascript:alert(1)]x[/url]")).toBe("[url=javascript:alert(1)]x[/url]");
        expect(bbcodeToHtml('[url=https://a.example/" onclick="x]y[/url]')).not.toContain('" onclick');
        expect(bbcodeToHtml("[list][*]a[*]b[/list]")).toBe("<ul><li>a</li><li>b</li></ul>");
        expect(bbcodeToHtml("[code][b]x[/b][/code]")).toBe("<pre><code>[b]x[/b]</code></pre>");
    });

    it("encodes HTML entities", () => {
        expect(encodeEntities('<a href="x">&</a>', false)).toBe("&lt;a href=&quot;x&quot;&gt;&amp;&lt;/a&gt;");
        expect(encodeEntities("ü", true)).toBe("&#xFC;");
    });

    it("parses URLs and decodes query parameters", () => {
        const rows = Object.fromEntries(parseUrl("example.com/a%20b?x=1&y=%C3%BC#top"));
        expect(rows.Host).toBe("example.com");
        expect(rows.Path).toBe("/a b");
        expect(rows["?y"]).toBe("ü");
        expect(rows.Fragment).toBe("#top");
    });

    it("runs the library based tools", async () => {
        const run = (slug: string, input: string) => {
            const tool = devTools.find((t) => t.slug === slug)!;
            const options = Object.fromEntries((tool.options ?? []).map((o) => [o.key, o.default]));
            return tool.run(input, options);
        };
        expect(await run("css-minifier", ".a { color: #ffffff; }")).toEqual({ kind: "text", value: ".a{color:#fff}" });
        expect(await run("js-minifier", "function f(longName) { return longName + 1 }")).toEqual({
            kind: "text",
            value: "function f(n){return n+1}",
        });
        expect(await run("sql-formatter", "select a from b")).toEqual({ kind: "text", value: "SELECT\n    a\nFROM\n    b" });
        expect(await run("markdown-to-html", "**x**")).toEqual({ kind: "html", value: "<p><strong>x</strong></p>\n" });
        const ua = await run("user-agent-parser", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36");
        expect(ua.kind === "table" && Object.fromEntries(ua.rows).Browser).toBe("Chrome 130.0.0.0");
    }, 60_000);

    it("has unique slugs", () => {
        expect(new Set(devTools.map((t) => t.slug)).size).toBe(devTools.length);
    });
});
