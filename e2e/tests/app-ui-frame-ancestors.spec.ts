/**
 * An operator names outside sites that may show app pages in a frame. App responses and the
 * dashboard's sign-in redirect allow those sites; login and the rest of the dashboard stay
 * unframeable, and an origin the setting cannot take stops startup.
 */
import { expect, layer } from "@effect/vitest";
import { Effect, Layer, Schema } from "effect";
import { createServer } from "node:http";
import { Api, body, SessionClients } from "../support/api.ts";
import { helloIndex } from "../support/app-authoring.ts";
import { appsManifest } from "../support/apps-release.ts";
import { Browser } from "../support/browser.ts";
import { TestLive, withCase } from "../support/case.ts";
import { App } from "../support/contracts.ts";
import { startFreshSelfHost } from "../support/managed-server.ts";
import { Target, driver } from "../support/platform.ts";
import { scenarios } from "../test-plan.ts";

const Organizations = Schema.NonEmptyArray(
  Schema.Struct({ id: Schema.String, slug: Schema.String }),
);
const Location = Schema.Struct({ status: Schema.Literal("ready"), url: Schema.String });
const email = "frame-owner@example.test";
const password = "Synthetic-frame-password-123!";

layer(TestLive, { excludeTestServices: true })("App UI frame ancestors", (it) => {
  it.effect(scenarios.appUiFrameAncestors.title, (context) =>
    withCase(
      context,
      Effect.gen(function* () {
        const target = yield* Target;
        const browser = yield* Browser;

        const refused = yield* Effect.scoped(
          startFreshSelfHost(target, {
            EXECUTOR_APP_UI_FRAME_ANCESTORS: "https://shell.example.test http://shell.example.test",
          }),
        ).pipe(Effect.flip);
        expect(refused.message).toContain("Each frame ancestor must be an origin");

        // The embedding site: a page on its own origin that frames the URL it is given.
        const embedder = yield* Effect.acquireRelease(
          driver(
            "start the embedding site",
            () =>
              new Promise<{ server: ReturnType<typeof createServer>; port: number }>(
                (resolve, reject) => {
                  const server = createServer((request, response) => {
                    const source = new URL(
                      request.url ?? "/",
                      "http://embedder.invalid",
                    ).searchParams.get("src");
                    response.setHeader("content-type", "text/html");
                    response.end(
                      `<!doctype html><title>Embedder</title><iframe title="App" src="${(source ?? "").replaceAll("&", "&amp;").replaceAll('"', "&quot;")}"></iframe>`,
                    );
                  });
                  server.once("error", reject);
                  server.listen(0, "127.0.0.1", () => {
                    const address = server.address();
                    if (address === null || typeof address === "string")
                      return reject(new Error("No embedder port"));
                    resolve({ server, port: address.port });
                  });
                },
              ),
          ),
          ({ server }) => Effect.sync(() => server.close()),
        );
        // App hosts are `<app>.<organization>.localhost`; a sibling under the organization's
        // label is the same site, so the app's SameSite=Lax session reaches the frame.
        const ancestors = `http://*.localhost:${embedder.port} https://shell.example.test`;
        const origin = yield* startFreshSelfHost(target, {
          EXECUTOR_APP_UI_FRAME_ANCESTORS: `http://*.localhost:${embedder.port}, https://shell.example.test`,
        });
        const api = yield* Api.pipe(
          Effect.provide(Layer.fresh(Api.layer)),
          Effect.provide(Layer.fresh(SessionClients.layer)),
          Effect.provideService(Target, { ...target, metadata: { ...target.metadata, origin } }),
        );
        const owner = yield* api.session();
        expect(
          (yield* api.request(owner, "POST", "/api/auth/self-host/setup", {
            name: "Frame Owner",
            email,
            password,
            organizationName: "Frame lab",
          })).status,
        ).toBe(200);
        const [organization] = yield* body(
          Organizations,
          yield* api.request(owner, "GET", "/api/auth/organization/list"),
        );
        const prefix = `/api/organizations/${organization.id}`;
        const deployed = yield* api.request(owner, "POST", `${prefix}/apps/deploy`, {
          name: "Notes",
          files: [
            { path: "index.ts", content: helloIndex },
            appsManifest,
            { path: "ui/index.html", content: "<!doctype html><title>Notes</title><h1>Notes</h1>" },
          ],
        });
        expect(deployed.status).toBe(200);
        const app = yield* body(App, deployed);
        const { url } = yield* body(
          Location,
          yield* api.request(owner, "GET", `${prefix}/apps/${app.id}/ui`),
        );

        // The first sign-in is top-level: the dashboard's login page cannot be framed.
        yield* browser.use("Open the app without a session", (page) => page.goto(url));
        yield* browser.use("Enter the owner's email", (page) =>
          page.getByLabel("Email", { exact: true }).fill(email),
        );
        yield* browser.use("Enter the owner's password", (page) =>
          page.getByLabel("Password", { exact: true }).fill(password),
        );
        yield* browser.use("Sign in", (page) =>
          page.getByRole("button", { name: "Sign in", exact: true }).click(),
        );
        yield* browser.use("Sign-in returns to the app", (page) =>
          page.getByRole("heading", { name: "Notes", exact: true }).waitFor(),
        );

        // Headers as this browser receives them, with its app and dashboard sessions, or as a
        // browser with neither.
        const headers = (path: string, base: string, signedIn = true) =>
          browser.use(`Read the headers of ${path}`, (page) =>
            (signedIn
              ? Promise.resolve(page.context())
              : (page.context().browser()?.newContext() ??
                Promise.reject(new Error("No browser for a fresh context")))
            ).then((context) =>
              context.request
                .get(new URL(path, base).href, {
                  maxRedirects: 0,
                  headers: { accept: "text/html" },
                })
                .then((response) => ({ status: response.status(), headers: response.headers() }))
                .finally(() => (signedIn ? undefined : context.close())),
            ),
          );
        const document = yield* headers("/", url);
        expect(document.status).toBe(200);
        expect(document.headers).toMatchObject({
          "content-security-policy": `frame-ancestors ${ancestors}`,
          "cache-control": "no-store",
          "referrer-policy": "no-referrer",
          "x-content-type-options": "nosniff",
        });
        // A response that carries no policy of its own gets the list too.
        const reserved = yield* headers("/_executor/not-found", url);
        expect(reserved.status).toBe(404);
        expect(reserved.headers["content-security-policy"]).toBe(`frame-ancestors ${ancestors}`);
        const failedCallback = yield* headers("/_executor/auth/callback", url);
        expect(failedCallback.status).toBe(401);
        expect(failedCallback.headers["content-security-policy"]).toBe(
          `default-src 'none'; frame-ancestors ${ancestors}; base-uri 'none'`,
        );
        const signIn = yield* headers("/", url, false);
        expect(signIn.status).toBe(302);
        expect(signIn.headers["content-security-policy"]).toBe(`frame-ancestors ${ancestors}`);
        const appAuth = signIn.headers.location ?? "";
        expect(new URL(appAuth).pathname).toBe("/app-auth");
        // The dashboard hop a framed page passes through allows the same sites.
        const granted = yield* headers(appAuth, origin);
        expect(granted.status).toBe(302);
        expect(new URL(granted.headers.location ?? "").pathname).toBe("/_executor/auth/callback");
        expect(granted.headers["content-security-policy"]).toBe(`frame-ancestors ${ancestors}`);
        // Every dashboard page, including login and app-auth's own page, stays unframeable.
        for (const path of ["/login", "/app-auth", `/org/${organization.slug}/apps`]) {
          const page = yield* headers(path, origin);
          expect(page.status, path).toBe(200);
          expect(page.headers["content-security-policy"], path).toContain("frame-ancestors 'none'");
        }

        const shell = new URL(`http://shell.${organization.slug}.localhost:${embedder.port}/`);
        shell.searchParams.set("src", url);
        yield* browser.use("Open the embedding site", (page) => page.goto(shell.href));
        yield* browser.use("The app renders inside the embedding site's frame", (page) =>
          page
            .frameLocator("iframe[title='App']")
            .getByRole("heading", { name: "Notes", exact: true })
            .waitFor(),
        );
        yield* browser.checkpoint("An app page in a named embedder's frame");
      }),
    ),
  );
});
