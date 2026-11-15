// ua-parser-js 1.x ships without type definitions; only the parts used here are declared.
declare module "ua-parser-js" {
    interface Part {
        name?: string;
        version?: string;
    }
    export class UAParser {
        constructor(ua?: string);
        getResult(): {
            browser: Part;
            engine: Part;
            os: Part;
            device: { vendor?: string; model?: string; type?: string };
            cpu: { architecture?: string };
        };
    }
}
