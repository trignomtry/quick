# QuickScript Agents

## Mission and Guardrails
- Deliver a strongly typed scripting language that feels ergonomic but never sacrifices compile-time guarantees.
- Generate and execute native code through LLVM with minimal overhead; every addition must preserve or improve runtime speed.
- Provide batteries-included async IO (HTTP, file, random, range) without leaking unsafe edges to user space.
- Keep the surface area small and predictable: new features should extend existing patterns instead of bypassing them.

## Agent Roster and Responsibilities

### Frontend Agent (Lexing + Parsing)
- Lives primarily in `src/main.rs:1271` onward (`TokenKind`, `Parser`, `Instruction`, `Expr`).
- Tokenizes source with escape-aware strings, comment stripping, and numeric normalization (`tokenize`, `format_float`).
- Builds a typed AST while rejecting syntactically invalid constructs early; ensures loops, functions, and blocks are structurally sound.
- Maintains `PreCtx` to track declared symbols, custom types, and imported module metadata without executing user code.
- Must short-circuit on lexical or parse errors to avoid feeding invalid input to later stages.

### Type System Agent
- Anchored around `Type`, `Custype`, and helpers like `merge_return_types`, `get_type_of_expr`, and `returns_on_all_paths` in `src/main.rs:1460`-`2920`.
- Enforces strong typing for primitives, lists, options, key-value maps, user objects/enums, and function signatures.
- Validates control-flow (e.g., functions must return on all paths, `maybe` branches keep option semantics intact, `for` operates over `io.range`).
- Guards interop boundaries: module imports only expose statically verifiable exports; callbacks (`io.listen`, `web` helpers) are signature-checked before codegen.
- Any new language surface must integrate with these checks before reaching LLVM.

### CodeGen Agent (LLVM Backend)
- Implemented by `Compiler` in `src/main.rs:3035` onward, using Inkwell to JIT compile AST into native code.
- Maps QuickScript types to LLVM types (`qtype_to_llvm`) and builds SSA IR with aggressive optimizations enabled.
- Handles closures, captured environments, loop scaffolding, short-circuit booleans, and structured returns.
- Emits globals/locals in a type-stable way; globals zero-initialized, locals hoisted for speed, and runtime values stored with explicit type metadata.
- Persists IR to `ll.v` for debugging; execution returns numeric exit status while keeping async servers alive when started.

### Runtime Agent (FFI + Async Services)
- Provides fast C interop for strings, allocation, file IO, and random numbers (`qs_obj_*`, `qs_str_*`, std libc wrappers at top of `main.rs`).
- Spins up Tokio runtimes and Hyper-based HTTP server (`io.listen`) with request/response structs bridged into QuickScript objects.
- Exposes `io` helpers (file read/write, random, range builders) and `web` helpers (text/json/page/redirect/error) as strongly typed functions.
- Ensures async tasks stay off the main thread and that the process parks once a server is running.
- Any extension here must respect safety: return owned C strings, close FILE* handles, and guard against null pointers.

### Module + Library Agent
- `use json: "json";` style imports load `./deps/<name>/lib.qx` without execution, only recording exported constants/functions/types.
- Standard libraries live under `deps/` (e.g., `deps/json/lib.qx` implements a typed tokenizer/parser, `deps/test/lib.qx` contains sample helpers).
- Main script (`main.qx`) demonstrates using modules, objects, async HTTP, and in-memory session storage.
- HTML fixtures under `test/` (e.g., `test/index.html`) support the web demo served through `io.listen`.

## Flow of Control
1. `main()` reads the target `.qx` file, lexes it, and halts on any token errors.
2. The parser constructs the AST while populating typing context and module metadata.
3. Static analysis confirms return coverage, type compatibility, and import safety.
4. `Compiler` lowers the program into LLVM IR, wires built-ins, and JITs to native code.
5. The resulting function executes immediately; if an HTTP server starts, the runtime keeps it alive.

## Development Priorities
- Preserve static guarantees: every new AST node or runtime helper must report deterministic types.
- Favor zero-copy or pointer-based interop when safe; avoid allocations inside tight loops.
- Widen functionality via modules or built-ins only after defining their types explicitly in `Type` and enforcing them in the parser.
- Keep async boundaries non-blocking and make sure any blocking fallback goes through the shared runtimes.

## Extension Checklist
- Update tokenizer/parser/type checker together when adding syntax.
- Extend `Type`/`Custype` and associated match arms before touching LLVM codegen.
- Add new runtime functions with both C-side declarations and safe wrappers inside `Compiler` helpers.
- Mirror changes in sample scripts or `deps/` libraries to showcase the feature while validating strong typing and performance.
