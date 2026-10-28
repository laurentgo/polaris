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

AI assistance disclosure: the research and first draft were prepared with an AI assistant and are being reviewed by the author. Code facts below were read on Polaris `main` at commit `9149181` (2026-10-28): **[V]** verified in code, **[I]** inferred, **[unknown]** not established.

## 1. Summary

Polaris accepts the Iceberg REST `referenced-by` parameter on `loadTable`, `loadCredentials` and `loadView` (generated from the 1.11 spec update) but never uses it. [V] `IcebergCatalogAdapter` receives the value and drops it; the handlers have no argument for it. As a result Polaris authorizes a table reached through a view exactly like a direct load. It cannot make chain-aware decisions or audit the chain, and it has no way to host definer-style views other than leaving the semantics entirely to engines.

This proposal brings the chain into the authorizer SPI in a **no-behavior-change first phase**, then discusses optional catalog-managed view security attributes. The authorization and trust model stay with the authorizer (built-in RBAC, OPA, Ranger, or a custom implementation), consistent with the Iceberg spec leaving them to catalogs.

## 2. Non-goals

- No change to the default RBAC behavior in Phase 1.
- No trust mechanism defined by the spec; Polaris stays neutral and lets the authorizer or operator decide.
- Out of scope: row/column policy enforcement, function endpoints (not implemented in the Polaris runtime [V]), dialect handling.

## 3. Current state

| Area | Finding |
|---|---|
| Authorizer SPI | `PolarisAuthorizer` with `resolveAuthorizationInputs(state, request)` and `authorize(state, request)`; `AuthorizationRequest(principal, intents)`; sealed `AuthorizationIntent` (single target, rename, ...). No free-form context or attributes slot [V]. Implementations: internal RBAC, OPA, Ranger, selected by `polaris.authorization.type` [V]. |
| Call sites | `CatalogHandler.resolveBasicTableLikeTargetOrThrow` builds a single-target intent; only the target is resolved into the manifest [V]. |
| `referencedBy` | Dropped in the adapter for all three endpoints; the event delegator forwards it but events carry no attribute for it [V]. No test exercises it [V]. No parser for the comma-separated format exists [V]. |
| Entity model | Views are `TABLE_LIKE` entities with `properties` (user-visible) and `internalProperties` (server-managed). View properties and SQL live in the metadata file [V]. A view entity is created with almost no internal properties [V]. No creator or owner concept in core [V]. |
| Identity | `PolarisPrincipal` has a name, roles and attributes (including the raw JWT when present). No first-class client or engine identity [V]. OPA receives only principal and roles, not token claims [V]. |
| Credentials | `loadTable` with delegation and `loadCredentials` share one authorization path, mapped to read/write data privileges; views vend nothing [V]. |
| ETag | On `loadTable`, authorization runs before the `If-None-Match` comparison [V]. The tag is a hash of the metadata location and does not vary by principal, delegation mode or `referencedBy` [V]. `loadView` has no ETag handling [V]. `Cache-Control`/`Vary`: none found in main code [unknown whether a filter adds them]. |
| Prior discussion | No issue, PR or thread on `referenced-by`, definer/invoker views or view owner found. A May 2025 dev@ thread ("Context-Aware Functions for Apache Polaris") proposed catalog-side view security functions; its replies have not been read. |

## 4. Proposal

### Phase 1: plumbing, no behavior change

1. Parse `referenced-by` in the adapter into an ordered list of identifiers: split on commas, split each entry on the last namespace separator from `/config`, decode `%2C`. Validate (depth limit, no duplicates, target not in the chain, same catalog) only when the feature is enabled, so nothing changes by default.
2. Pass the chain to the handlers for `loadTable`, `loadCredentials` and `loadView`.
3. Carry it into the authorizer SPI. Preferred shape: an optional list of securables on the single-target intent, visited by the existing securable visitor so current selectors and resolvers pick it up [I]. Alternatives: a general context/attributes field on `AuthorizationRequest`; new "load via view" operations (not preferred: this multiplies the operation and privilege tables).
4. Add the chain views to the resolution manifest, using the same passthrough-path mechanism already used for namespace operations.
5. OPA: add the chain as an additive input (for example `resource.referenced_by[]`). Ranger: pass-through per its model. The default RBAC authorizer ignores it.
6. Include the chain in events so it is auditable.
7. Gate with a feature flag (for example `ENABLE_REFERENCED_BY_AUTHORIZATION`, default false, per catalog) following the existing `FeatureConfiguration` pattern.
8. Tests: adapter parsing, chain resolution, OPA input, and authorization tests alongside the existing handler authorization tests.

### Phase 2 (separate, optional): reference behavior in the built-in authorizer

Only if the community wants a built-in implementation rather than leaving it to external authorizers.

- **Catalog-managed attributes.** Store the creating principal and an optional security mode (definer or invoker) in the view entity's `internalProperties`, stamped by the catalog at creation and never read from metadata-file properties (those are writer-controlled, and `registerView` imports external metadata). Internal properties are preserved across updates [V].
- **Mode source.** Default invoker. A definer request needs a source: an engine-supplied property honored only from a trusted caller (as Lakekeeper does with `trino.run-as-owner`), or a Polaris-specific management API. The Iceberg spec does not define one.
- **Trust.** Operator-defined. Options: (a) leave to external authorizers; (b) express trust through existing RBAC, for example a dedicated privilege granted to engine principals; (c) a small SPI mapping a principal and its token claims to "may assert a chain". Polaris has no engine identity today, so a trust signal would derive from principal name, roles or JWT claims.
- **Evaluation.** For a chain from a trusted caller: require access to the outermost view for the caller; at each view whose mode is definer, evaluate the next hop for the stored creating principal (resolved to its roles); evaluate the target the same way. An invoker view keeps the current principal. Every entity is authorized on every request; early exit only on denial. Batching per principal segment (one authorizer call per run of hops evaluated for the same principal) is a reasonable cost model.
- **Credentials.** The same authorization path covers vending.

### Cross-cutting

- **ETags.** Authorization already runs before the ETag check, so a 304 cannot leak. If a chain-dependent response differs (credentials, config or policy), the tag must vary; today it is the metadata location only.
- **Federated catalogs.** The federated REST factory does not appear to forward `referencedBy` upstream [I, not read in depth]. Default: do not forward; open question.
- **Functions.** Out of scope until Polaris implements them and the Iceberg spec defines how functions appear in a chain.

## 5. Security considerations

- The chain is client-asserted. Phase 1 changes nothing. In Phase 2, without a trust gate any caller could claim a chain and borrow the stored principal's access; the gate must default to "no one trusted".
- A trusted engine can name a view and then request an unrelated table. Either accept this (trust is explicit and audited), or validate that the target is actually referenced by the last view, which Polaris cannot do from view SQL alone. Open.
- Replacing the SQL of a definer view must not be possible for a principal other than the owner or an admin, or the owner's access can be borrowed. Today `REPLACE_VIEW` needs only the view write privileges.
- Credentials vended through a chain are bearer secrets: scope them to the table and keep lifetimes short.
- The stored principal can be deleted or lose roles: define the failure behavior as deny, never fall back to the caller.
- `registerView` must not import any security attribute from the supplied metadata.
- Audit must record the caller, the chain, the principals evaluated at each hop and the decision.

## 6. Open questions

1. **Full chain or parent only.** The Iceberg dev list discussed this in February 2026 ("Granularity of referenced-by context"). The spec merged with the full chain and the Iceberg Java client sends it, so Polaris should accept the full chain and let the authorizer use what it needs. Confirm no change is pending.
2. An intent field versus a general context on `AuthorizationRequest`: which fits the SPI's direction?
3. Is a built-in definer implementation (Phase 2) wanted, or should it stay with OPA, Ranger and custom authorizers?
4. How should trust be expressed (Phase 2 options)?
5. Where should a definer request originate: an engine-supplied property or a Polaris-specific API?
6. Should `loadView` get ETag support, and should `Cache-Control`/`Vary` be added for credential-bearing responses?
7. What did the 2025 context-aware-functions thread conclude, and does it overlap?

## 7. Process and next steps

1. Read the dev@ replies of the 2025 thread, the SPI RFC linked from #3779, and the recent SPI pull requests, to align naming.
2. Reach out informally to the SPI authors, the `referenced-by` authors and the Lakekeeper maintainers before posting.
3. Open a `proposal` issue and design doc and start the dev@ discussion; propose Phase 1 as the first PR, Phase 2 only after agreement.
4. Keep the SPI shape aligned so downstream forks that need Phase 1 earlier can converge on upstream later.

## 8. Prior art

Lakekeeper documents a trusted-engine model: the owner stored in an engine-specific property, only trusted engines may set it, the chain honored only for trusted callers, evaluation switching at definer boundaries, a depth limit, and audit with the full chain. It is the reference for Phase 2 semantics, not a mandate.
