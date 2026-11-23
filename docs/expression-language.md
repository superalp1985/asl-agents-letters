# ASL/1.1 expression letters

An expression letter carries a finite symbolic statement, request, or other
term. It is not a search plan, an executable program, or a way to invoke a
tool. Decoding validates structure and scope only. It does not run operations,
expand definitions, resolve concepts, infer truth, or authorize any action.

## Envelope

An `ExpressionLetter` is control frame kind `15`, with wire version `1`.
Its deterministic CBOR map is defined by `expression-letter` in
[`schemas/asl-v1.cddl`](../schemas/asl-v1.cddl).

| Key | Field | CBOR |
| --- | --- | --- |
| `0` | Version | `1` |
| `1` | Kind | `15` |
| `2` | `message_id` | 16-byte ID for this letter |
| `3` | `root_task_id` | 16-byte ID for its task |
| `4` | `created_at_ms` | Unix time in milliseconds |
| `5` | `expires_at_ms` | Unix time in milliseconds |
| `6` | `expression` | One term |

All keys are required. The decoder requires
`0 <= created_at_ms <= expires_at_ms <= 9223372036854775807` without
consulting a clock. The existing 65,536-byte control-frame limit and
deterministic CBOR rules apply. Send only to a peer with Hello major `1`,
minor `>=1`; this adds no Hello feature. The same letter can be carried
inside an authenticated MLS group application without changing its outer envelope.

## Term Syntax

Every term is a fixed-shape array. In CBOR the first item is the numeric
tag; local JSON uses the mnemonic instead. In the table, capitalized
placeholders stand for terms, `[...]` for a list, and `C` for a literal
qualified `concept` term, not an expression that computes one.

| CBOR tag | Local JSON | Meaning |
| --- | --- | --- |
| `0` | `["int", m]` | Signed 64-bit integer. |
| `1` | `["decimal", m, scale]` | Exact `m * 10^-scale`; `scale` is `1..18`. |
| `2` | `["bool", b]` | `true` or `false`. |
| `3` | `["op", op, A]` or `["op", op, A, B]` | Built-in operator of the exact arity below. |
| `4` | `["var", depth]` | Reference into the variable scope. |
| `5` | `["let", Value, Body]` | Bind `Value` as a variable in `Body`. |
| `6` | `["define", arity, Definition, Body]` | Introduce a local symbol with a structural definition. |
| `7` | `["call", depth, [A, ...]]` | Denote a local symbol instantiated with arguments. |
| `8` | `["if", Condition, Then, Else]` | Denote `Then` when the condition is true and `Else` when false. Both branches must be structurally valid. |
| `9` | `["request", Content]` | Ask the recipient to respond to the content; no implied tool, search, or side effect. |
| `10` | `["assert", Content]` | Present the content as holding according to the sender; not proof. |
| `11` | `["tuple", [A, ...]]` | Ordered collection of terms; no execution order. |
| `12` | `["concept", authority, namespace, revision, id]` | Qualified external concept atom. |
| `13` | `["meaning", C]` | Ask for the meaning of this exact concept. |
| `14` | `["meaning_is", C, arity, Definition]` | Supply a structural meaning claim for this exact concept. |
| `15` | `["apply", C, [A, ...]]` | Denote an external concept applied to arguments; not a local call. |

`m` is a CBOR integer and, in local JSON only, its exact base-10 spelling
as a string (`"0"`, `"-42"`, `"9223372036854775807"`). No plus sign,
leading zeros, negative zero, decimal points, or exponent notation. This
preserves i64 values even through JavaScript. Decimal scale is preserved
structurally; `["decimal","10",1]` and `["int","1"]` have the same numeric
meaning but different encodings. `authority` is a 32-byte ASL `AgentId`
in CBOR and 64 lowercase hexadecimal digits in JSON. All other unsigned
fields are numbers in JSON, not strings. The authority field represents
an identifier only. There are no text literals, general byte strings,
maps, embedded source, CBOR floats, or CBOR tags in an expression.

The root counts as one node at depth one. Maximum depth is eight terms,
maximum total size is 256 terms, and every term list and definition arity
is `0..16`. An embedded concept term counts as a node, but metadata
scalars and list containers do not. Reference depths are unsigned bytes
and must resolve to existing entries. In addition to the CDDL grammar,
decoders enforce lexical scope, call arity, term depth/count, and the
envelope's timestamp order. Unknown tags, operators, and fields are errors.

### Operators

| CBOR | JSON | Arity | Denotation |
| --- | --- | --- | --- |
| `0`, `1`, `2`, `3` | `add`, `sub`, `mul`, `div` | 2 | Exact numeric arithmetic, including rational division. |
| `4` | `neg` | 1 | Numeric negation. |
| `5`, `6` | `eq`, `ne` | 2 | Equality and inequality. |
| `7`, `8`, `9`, `10` | `lt`, `le`, `gt`, `ge` | 2 | Numeric comparisons. |
| `11`, `12` | `and`, `or` | 2 | Boolean conjunction and disjunction. |
| `13` | `not` | 1 | Boolean negation. |

The operator mnemonic occupies the second slot in JSON; its code occupies
that slot in CBOR. Arithmetic and comparisons are over mathematical
values in operand order, not wrapping machine integers. Equality compares
numeric values across integer and decimal forms, Booleans by value,
qualified atoms by all four fields, and tuples element by element in order.
Known values from different domains are unequal, except for the shared
numeric domain. A numeric or Boolean operator on incompatible operands,
division by zero, or a non-Boolean condition has no defined value.
Unresolved terms can be kept symbolic. These are meanings of the terms,
not evaluation, simplification, or type-checking requirements on a codec.

### Lexical References

A letter starts with empty variable and local-symbol stacks. Each
reference is zero-based within its own stack: `0` is nearest, `1` is the
next, and so on. Neither stack is shared with other letters.

- `let` parses its value in the incoming scope, then pushes one variable
  for its body only. An inner `let` shadows outer variables by adding a
  new slot, not by changing their bindings.
- `define` parses its definition in the lexical environment at the
  declaration, with parameters prepended to the variable stack. Parameter
  zero is argument zero, parameter one is argument one, etc. For arity
  `n`, the previous variable at depth `0` is now at depth `n` in
  `Definition`. The new symbol is not in scope in its own definition; an
  existing outer symbol at depth `0` still denotes that outer symbol.
- `define` pushes the new symbol for `Body` only; it does not push its
  parameters there. `call` resolves the symbol in the caller's symbol
  stack, and its arguments are terms in the caller's scope. The referenced
  definition's free bindings remain those from its declaration, never
  the caller's. Arguments must match the declared arity exactly.

These rules exclude recursive or forward local references. A receiver
can retain the compact tree and bindings; it need not perform substitution
or expand repeated calls.

### Qualified Concepts

External references are optional. A concept's identity is exactly
`(authority, namespace:u32, revision:u16, id:u32)`. The authority
identifies the owner of the namespace; revisions are distinct, and there
are no defaults or implicit mappings to the Query vocabulary. The
receiver can preserve an unknown qualifier and send `meaning` back to
the peer on the same `root_task_id` in a new letter. The qualifier itself
is neither a network locator nor proof that the sender speaks for its
authority.

`meaning_is` describes a concept with a definition whose only initial
bindings are its own parameters, numbered in argument order. It cannot
capture surrounding variables or local symbols; it can introduce its own
bindings. Arity zero describes the concept atom; other arities describe
its application with exactly that many arguments. Applications of
unknown concepts are admissible without resolving their arity. A
`meaning_is` is the sender's claim, not an instruction to install a
definition or expand it on receipt. A receiver may compare descriptions
under its own authenticity and trust policy. No cross-letter definition
is created by the codec, and no resolution is required for interoperation.

## MCP Representation

Pass one JSON term to `Expression::from_json(&serde_json::Value)`;
`Expression::to_json()` returns the same tagged-array representation.
These helpers do not accept or return the envelope. Malformed terms
return `AslError::InvalidMessage`. An MCP property named `expression`
can advertise this coarse JSON Schema and use the Rust helper for strict
validation (including recursive syntax and scope):

```json
{
  "type": "array",
  "minItems": 2,
  "maxItems": 5,
  "description": "One ASL expression term as a tagged array; see the ASL expression grammar."
}
```

## Worked Exchange

The fixed vector `expression-letter-v1` carries this term:

```json
["let", ["int", "3"],
  ["define", 1, ["op", "add", ["var", 0], ["var", 1]],
    ["if", ["op", "lt", ["call", 0, [["int", "4"]]], ["int", "8"]],
      ["assert", ["op", "eq", ["call", 0, [["int", "5"]]], ["int", "8"]]],
      ["meaning", ["concept", "abababababababababababababababababababababababababababababababab", 4, 1, 27]]
    ]
  ]
]
```

The definition's `var 0` is its incoming argument and `var 1` is the
captured `3`. `call 0` denotes that definition in both places. By hand,
the condition is `4 + 3 < 8`, so the assertion says `5 + 3 = 8`.
There is no need to know the external concept to interpret that assertion.
If an agent wants to understand the alternative independently, it can send
the `meaning` term as a standalone letter. A peer could reply:

```json
["meaning_is", ["concept", "abababababababababababababababababababababababababababababababab", 4, 1, 27],
  1, ["op", "gt", ["var", 0], ["int", "8"]]]
```

The reply proposes that the exact qualified concept denotes "greater than
eight" when applied to one argument. Under that interpretation, an agent
can read the following as a request to answer whether `10 > 8`:

```json
["request", ["apply", ["concept", "abababababababababababababababababababababababababababababababab", 4, 1, 27],
  [["int", "10"]]]]
```

### Replying From a Host

1. Subscribe to `asl://agent/inbound-events`. On `notifications/resources/updated`,
   read that resource. Process new entries by `sequence`, not by repeatedly
   answering every entry in the snapshot.
2. For a direct `expression` event, take `target` from `event.details.agent`.
   For a reply to the same group, take it from `event.details.room`, even
   though the event also names its individual author. Take `root` from
   `event.details.root_task_id`, not from the latest `message_id`.
3. For example, when the incoming expression is `["meaning", C]` and the
   local agent knows a definition for `C`, call `asl_send_expression` with
   arguments constructed as follows (local pseudocode, not wire syntax):

   ```text
   target     = details.room if details.room is not null else details.agent
   root       = details.root_task_id
   expression = ["meaning_is", C, 1, ["op", "gt", ["var", 0], ["int", "8"]]]
   ```

   These fields are separate tool arguments. On a new task omit `root`;
   Core creates it from the first letter's ID. Each subsequent reply gets
   a new message ID. Do not substitute an unknown concept for one that
   only seems similar. A host may ask for clarification or choose not to
   reply. A `policy_denied` result is not permission to try a different
   destination or communication channel.
