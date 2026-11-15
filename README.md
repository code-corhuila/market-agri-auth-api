# market-agri-auth-api

> auth bounded context: service API

Part of the **Marketplace Agrícola Huila** distributed system.
Governance and documentation live in [`market-agri-docs`](https://github.com/code-corhuila/market-agri-docs).

- **API contract:** `07-api/api-contract.md` §4.1 and `07-api/contracts/openapi/service-auth.yaml`
  in `market-agri-docs`.
- **Schema and migrations:** `market-agri-auth-db`. This repository never versions the schema.

## Structure (Annex C — Java, three Maven modules)

| Module | Contains | Depends on |
|---|---|---|
| `auth-core` | Domain, input/output ports, use cases. Plain Java: no Spring, no JDBC | nothing |
| `auth-adapters` | HTTP input adapter, persistence output adapters | `auth-core` |
| `auth-app` | Composition root: wiring (`@Bean`), `application.yml`, the executable jar | everything |

`auth-core` does not declare any framework: a `@Service`, `@Entity` or `@RestController` there does
not compile.

## Run

```bash
mvn -B verify                                  # build and test (what ci.yml runs)
cp .env.example .env                           # then fill in real values
docker compose -f deploy/compose.yml config    # validate the service definition
```

In the platform, `market-agri-infra` includes `deploy/compose.yml`; the service is reachable only
through the API Gateway.

## Branching

Three permanent branches. **None of them accepts a direct commit** — you enter through a child
branch and leave through a Pull Request.

```
develop  <--PR--  feat/... fix/... chore/...
qa       <--PR--  qa/...
main     <--PR--  release/...  hotfix/...
```

Promotion happens **by re-application** (`git cherry-pick -x`), never by merging one permanent
branch into another: `merge develop -> qa` and `merge qa -> main` do not exist in this model.

`main` requires **1 approval from `ariel5253`**. On `develop` and `qa` the team sets its own review
rule.

Full policy: `00-governance/branching-policy.md` in `market-agri-docs`.
