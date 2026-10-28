<!--
  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
-->

# Proposal: Chain-Aware Authorization for Views (`referenced-by`)

Author: Laurent Goujon. Status: **early draft for informal review, not yet submitted to dev@ or opened as a proposal issue.** This file lives in a personal fork only to gather feedback from a few people first; it is not intended to be merged.

AI assistance disclosure: the research and first draft were prepared with an AI assistant and are being reviewed by the author.

Every statement about current Polaris behavior was checked in the source of Polaris `main` at commit `9149181` (2026-10-28). What could not be established is listed as an open question.

## 1. Summary

Polaris accepts the Iceberg REST `referenced-by` parameter on `loadTable`, `loadCredentials` and `loadView` (from the Iceberg 1.11 spec update) but never uses it. `IcebergCatalogAdapter` receives the value and drops it, and the handlers have no argument for it. As a result Polaris authorizes a table reached through a view exactly like a direct load. It cannot make chain-aware decisions or audit the chain, and it has no way to host definer-style views other than leaving the semantics entirely to engines.

This proposal brings the chain into the authorizer SPI in a **no-behavior-change first phase**, then discusses optional catalog-managed view security attributes in a separate second phase. The authorization and trust model stay with the authorizer (built-in RBAC, OPA, Ranger, or a custom implementation), consistent with the Iceberg spec leaving them to catalogs.

## 2. Non-goals

- No change to the default RBAC behavior in Phase 1.
- No trust mechanism defined by the spec; Polaris stays neutral and lets the authorizer or operator decide.
- Out of scope: row/column policy enforcement, dialect handling, and function endpoints (the Polaris runtime has no implementation of `loadFunction`).

## 3. Current state

| Area | Finding |
|---|---|
| Authorizer SPI | `PolarisAuthorizer` with `resolveAuthorizationInputs(state, request)` and `authorize(state, request)`. `AuthorizationRequest` holds a principal and a list of intents; `AuthorizationIntent` is a sealed interface (single target, rename, and others) with a `visitSecurables` method. The request and intents have no free-form context or attributes field. Implementations: internal RBAC, OPA and Ranger, selected by `polaris.authorization.type`. |
| Call sites | `CatalogHandler.resolveBasicTableLikeTargetOrThrow` builds a single-target intent, so only the target table-like is resolved. |
| `referencedBy` | The adapter declares it on `loadTable`, `loadCredentials` and `loadView` and never uses it. The event delegator passes it to the delegate; `EventAttributes` has no attribute for it. No source code parses the comma-separated format, and no test mentions `referencedBy` or `referenced-by`. `IcebergRESTFederatedCatalogFactory` does not reference it. |
| Entity model | Views are `TABLE_LIKE` entities with subtype `ICEBERG_VIEW`, with `properties` (user-visible) and `internalProperties` (server-managed). A view entity is created from its identifier and metadata location only (`LocalIcebergCatalog`, view commit). No creator or owner attribute exists in `polaris-core` or `runtime/service` main sources. |
| Identity | `PolarisPrincipal` exposes a name, roles and an attribute map, which includes the raw JWT for token-authenticated callers (`DefaultAuthenticator`). It has no dedicated client or engine field. The OPA actor carries only the principal name and roles. |
| Authorization of views | `REPLACE_VIEW` requires `VIEW_WRITE_PROPERTIES`; `LOAD_VIEW` requires `VIEW_READ_PROPERTIES`. |
| Credentials | `loadTable` with delegation and `loadCredentials` both call `authorizeLoadTable`. `loadView` returns the view metadata only. |
| ETag | On `loadTable`, `authorizeLoadTable` runs before the `If-None-Match` comparison. The tag is generated from the metadata location alone (`IcebergHttpUtil.generateETagForMetadataFileLocation`), so it does not vary by principal, delegation mode or `referencedBy`. `loadView` takes no `If-None-Match` and sets no ETag. No `Cache-Control` or `Vary` occurs in `runtime` or `polaris-core` main sources, properties or YAML files. |
| Prior discussion | Searches of apache/polaris issues and pull requests found nothing on `referenced-by`, definer or invoker views, or view owner. A May 2025 dev@ thread, "Context-Aware Functions for Apache Polaris" (Prashant Singh), proposed catalog-side functions for views to resolve the security context; the replies have not been read yet. |

## 4. Proposal

### Phase 1: plumbing, no behavior change

1. Parse `referenced-by` in the adapter into an ordered list of identifiers: split on commas, split each entry on the last namespace separator from `/config`, decode `%2C`. Validate (depth limit, no duplicates, target not in the chain, same catalog) only when the feature is enabled, so nothing changes by default.
2. Pass the chain to the handlers for `loadTable`, `loadCredentials` and `loadView`.
3. Carry it into the authorizer SPI. Preferred shape: an optional list of securables on the single-target intent, exposed through the existing `visitSecurables` hook, which `NonRBACResolutionSemantics` uses to select entities. Alternatives: a general context or attributes field on `AuthorizationRequest`; new "load via view" operations (not preferred, because they multiply the operation and privilege tables).
4. Add the chain views to the resolution manifest with `addPassthroughPath`, the mechanism `CatalogHandler` already uses for extra passthrough namespaces and table-likes.
5. OPA: add the chain as an additive input (for example `resource.referenced_by[]`). Ranger: pass-through per its model. The default RBAC authorizer ignores it.
6. Add the chain to events so it is auditable.
7. Gate with a feature flag (for example `ENABLE_REFERENCED_BY_AUTHORIZATION`, default false, per catalog) following the existing `FeatureConfiguration` pattern.
8. Tests: adapter parsing, chain resolution, OPA input, and authorization tests alongside the existing handler authorization tests.

### Phase 2 (separate, optional): reference behavior in the built-in authorizer

Only if the community wants a built-in implementation rather than leaving it to external authorizers.

- **Catalog-managed attributes.** Store the creating principal and an optional security mode (definer or invoker) in the view entity's `internalProperties`, stamped by the catalog at creation. Updates to a view build the new entity from the existing one, and the builder copies its internal properties, so the attributes persist. They must never be read from view metadata supplied by clients, including through `registerView`, because that metadata is writer-controlled.
- **Mode source.** Default invoker. A definer request needs a source: an engine-supplied property honored only from a trusted caller (as Lakekeeper does with `trino.run-as-owner`), or a Polaris-specific management API. The Iceberg spec does not define one.
- **Trust.** Operator-defined. Options: (a) leave to external authorizers; (b) express trust through existing RBAC, for example a dedicated privilege granted to engine principals; (c) a small SPI mapping a principal and its token claims to "may assert a chain".
- **Evaluation.** For a chain from a trusted caller: require access to the outermost view for the caller; at each view whose mode is definer, evaluate the next hop for the stored creating principal (resolved to its roles); evaluate the target the same way. An invoker view keeps the current principal. Every entity is authorized on every request; early exit only on denial. Lakekeeper groups consecutive hops evaluated for the same principal into one authorizer call, which is a reasonable cost model.
- **Credentials.** The same authorization path covers vending, because `loadTable` with delegation and `loadCredentials` share `authorizeLoadTable`.

### Cross-cutting

- **ETags.** Authorization already runs before the ETag check on `loadTable`, so a 304 cannot be returned to a caller who fails authorization. If a chain-dependent response differs (credentials, config or policy), the tag must vary; today it depends on the metadata location only.
- **Federated catalogs.** Nothing forwards `referencedBy` to a federated catalog today. Default: do not forward. Open question.
- **Functions.** Out of scope until Polaris implements function endpoints and the Iceberg spec defines how functions appear in a chain.

## 5. Security considerations

- The chain is client-asserted. Phase 1 changes nothing. In Phase 2, without a trust gate any caller could claim a chain and borrow the stored principal's access; the gate must default to "no one trusted".
- A trusted engine can name a view and then request an unrelated table. Either accept this (trust is explicit and audited), or validate that the target is actually referenced by the last view, which Polaris cannot do from view SQL alone. Open.
- Replacing the SQL of a definer view must not be possible for a principal other than the owner or an admin, or the owner's access can be borrowed. Today `REPLACE_VIEW` requires only `VIEW_WRITE_PROPERTIES`.
- Credentials vended through a chain are bearer secrets: scope them to the table and keep lifetimes short.
- The stored principal can be deleted or lose roles: define the failure behavior as deny, never fall back to the caller.
- `registerView` must not import any security attribute from the supplied metadata.
- Audit must record the caller, the chain, the principals evaluated at each hop and the decision.

## 6. Open questions

1. **Full chain or parent only.** The Iceberg dev list discussed this in February 2026 ("Granularity of referenced-by context"). The spec merged with the full chain and the Iceberg Java client sends it (apache/iceberg#18015), so Polaris should accept the full chain and let the authorizer use what it needs. Confirm no change is pending.
2. An intent field versus a general context on `AuthorizationRequest`: which fits the SPI's direction?
3. Is a built-in definer implementation (Phase 2) wanted, or should it stay with OPA, Ranger and custom authorizers?
4. How should trust be expressed (Phase 2 options)?
5. Where should a definer request originate: an engine-supplied property or a Polaris-specific API?
6. Should `loadView` get ETag support, and should `Cache-Control` and `Vary` be added for credential-bearing responses?
7. What did the 2025 context-aware-functions thread conclude, and does it overlap?

## 7. Process and next steps

1. Read the dev@ replies of the 2025 thread, the SPI RFC linked from #3779, and the recent SPI pull requests, to align naming.
2. Reach out informally to the SPI authors, the `referenced-by` authors and the Lakekeeper maintainers before posting.
3. Open a `proposal` issue and design doc and start the dev@ discussion; propose Phase 1 as the first PR, Phase 2 only after agreement.
4. Keep the SPI shape aligned so downstream forks that need Phase 1 earlier can converge on upstream later.

## 8. Prior art

Lakekeeper documents a trusted-engine model: the owner stored in an engine-specific property, only trusted engines may set it, the chain honored only for trusted callers, evaluation switching at definer boundaries, a depth limit (default 10), and audit with the full chain. It is the reference for Phase 2 semantics, not a mandate.
