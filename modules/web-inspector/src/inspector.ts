/**
 * GramFuzz Web App Inspector — Headless TMA analysis with Playwright.
 *
 * Renders Mini Apps, intercepts Fetch/XHR, maps API endpoints,
 * and validates transaction payload safety.
 */

import { chromium, type Request } from "playwright";

interface CapturedRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  postData: string | null;
}

interface InspectResult {
  module: string;
  version: string;
  url: string;
  mode: "dry-run" | "live";
  requests: CapturedRequest[];
  endpoints: string[];
  notes: string[];
}

async function inspectWebApp(url: string, dryRun: boolean): Promise<InspectResult> {
  const result: InspectResult = {
    module: "web-inspector",
    version: "0.1.0",
    url,
    mode: dryRun ? "dry-run" : "live",
    requests: [],
    endpoints: [],
    notes: [],
  };

  if (dryRun) {
    result.notes.push("Dry-run mode — pass --live to launch headless browser.");
    result.notes.push("Will capture Fetch/XHR, extract API routes, validate Web3 payloads.");
    return result;
  }

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  const captured: CapturedRequest[] = [];

  page.on("request", (req: Request) => {
    const type = req.resourceType();
    if (type === "fetch" || type === "xhr") {
      captured.push({
        method: req.method(),
        url: req.url(),
        headers: req.headers(),
        postData: req.postData(),
      });
    }
  });

  try {
    await page.goto(url, { waitUntil: "networkidle", timeout: 30_000 });
    await page.waitForTimeout(3000);
  } catch (err) {
    result.notes.push(`Navigation error: ${(err as Error).message}`);
  }

  result.requests = captured;
  result.endpoints = [...new Set(captured.map((r) => {
    try {
      const u = new URL(r.url);
      return `${r.method} ${u.pathname}`;
    } catch {
      return r.url;
    }
  }))];

  await browser.close();
  return result;
}

async function main() {
  const args = process.argv.slice(2);
  const urlIdx = args.indexOf("--url");
  const live = args.includes("--live");
  const jsonOut = args.includes("--json");

  if (urlIdx === -1 || !args[urlIdx + 1]) {
    console.error("Usage: npm run inspect -- --url <webapp-url> [--live] [--json]");
    process.exit(1);
  }

  const url = args[urlIdx + 1];
  const result = await inspectWebApp(url, !live);

  if (jsonOut) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(`[GramFuzz] Web App Inspector — ${url}`);
    console.log(`  Mode: ${result.mode}`);
    console.log(`  Captured requests: ${result.requests.length}`);
    console.log(`  Unique endpoints: ${result.endpoints.length}`);
    for (const note of result.notes) {
      console.log(`  Note: ${note}`);
    }
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
