# Namespaces

A Namespace is the top-level isolation scope for identifiers, principals and authority roots, mutable packs, work, executions, Baselines, the event journal, policies, providers and registered extensions. It is not a product concept; consumers may map projects, environments or tenants onto Namespaces.

**AEVC-NS-0001** `CreateNamespace` may only be executed by a runtime administrator (configured out of band). It names one or more key-bearing root principals, who hold all authority within the Namespace.

**AEVC-NS-0002** Every mutable aggregate belongs to exactly one Namespace and every request envelope (except `CreateNamespace`) names its Namespace. Capability grants are Namespace-scoped.

**AEVC-NS-0003** Cross-Namespace references are forbidden, except importing immutable objects by digest through object exchange (object-exchange.md). Objects are visible in a Namespace only when indexed there, even if the bytes are stored once physically.

## Names

Kinds, fact names, metadata keys and other extensible names are _namespaced names_: two or more dot-separated lowercase segments (`[a-z0-9]` with inner `-` or `_`), optionally followed by `/`-separated path segments, at most 128 bytes. Examples: `kv.entry`, `org.example.kv/size`. Extension identifiers are namespaced names without a path part (reverse-DNS style).

**AEVC-NS-0004** Metadata, intent, annotation, attribute and constraint map keys MUST be namespaced names; requests violating this fail with `INVALID_ARGUMENT`.
