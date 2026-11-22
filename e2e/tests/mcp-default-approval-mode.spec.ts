/**
 * An operator chooses the approval mode a personal access token serves at the plain MCP URL. A
 * URL that names a mode still serves that mode, and a value that is not a mode stops startup.
 */
import { expect, layer } from "@effect/vitest";
import { Effect, Layer, Redacted, Schema } from "effect";
import { Api, body, SessionClients } from "../support/api.ts";
import { TestLive, withCase } from "../support/case.ts";
import { startFreshSelfHost } from "../support/managed-server.ts";
import { Target } from "../support/platform.ts";
import { rawRequest } from "../support/role-hosts.ts";
import { scenarios } from "../test-plan.ts";

const Organizations = Schema.NonEmptyArray(Schema.Struct({ id: Schema.String }));
const Token = Schema.Struct({ key: Schema.RedactedFromValue(Schema.String) });
const Whoami = Schema.Struct({ mode: Schema.String });

layer(TestLive, { excludeTestServices: true })("MCP default approval mode", (it) => {
  it.effect(scenarios.mcpDefaultApprovalMode.title, (context) =>
    withCase(
      context,
      Effect.gen(function* () {
        const target = yield* Target;

        const refused = yield* Effect.scoped(
          startFreshSelfHost(target, { EXECUTOR_MCP_DEFAULT_APPROVAL_MODE: "yolo" }),
        ).pipe(Effect.flip);
        expect(refused.message).toContain("EXECUTOR_MCP_DEFAULT_APPROVAL_MODE must be one of");

        const origin = yield* startFreshSelfHost(target, {
          EXECUTOR_MCP_DEFAULT_APPROVAL_MODE: "automatic",
        });
        const api = yield* Api.pipe(
          Effect.provide(Layer.fresh(Api.layer)),
          Effect.provide(Layer.fresh(SessionClients.layer)),
          Effect.provideService(Target, { ...target, metadata: { ...target.metadata, origin } }),
        );
        const owner = yield* api.session();
        expect(
          (yield* api.request(owner, "POST", "/api/auth/self-host/setup", {
            name: "Mode Owner",
            email: "mode-owner@example.test",
            password: "Synthetic-mode-password-123!",
            organizationName: "Mode lab",
          })).status,
        ).toBe(200);
        const [organization] = yield* body(
          Organizations,
          yield* api.request(owner, "GET", "/api/auth/organization/list"),
        );
        const { key } = yield* body(
          Token,
          yield* api.request(owner, "POST", "/api/auth/api-key/create", { name: "agent" }),
        );
        const modeAt = (query: string) =>
          Effect.gen(function* () {
            const response = yield* rawRequest(`${origin}/mcp/whoami${query}`, {
              headers: {
                authorization: `Bearer ${Redacted.value(key)}`,
                "x-executor-organization": organization.id,
              },
            });
            expect(response.status, response.text).toBe(200);
            return (yield* Schema.decodeUnknownEffect(Schema.fromJsonString(Whoami))(response.text))
              .mode;
          });

        expect(yield* modeAt("")).toBe("automatic");
        expect(yield* modeAt("?elicitation_mode=model")).toBe("model");
        expect(yield* modeAt("?elicitation_mode=browser")).toBe("browser");
      }),
    ),
  );
});
