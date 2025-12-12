# QuickScript

QuickScript is a micro-precise language built for Direct Execution. It keeps a predictable mental model while giving you Flow I/O, Web Primitives, ranges, objects, and typed Forms backed by Static Trust. The Kit stays small, performance stays metal-fast, and every new feature follows the same Patterns so nothing ever feels bolted on. The goal is simple: compiled-level speed, zero surprises, and an API surface you can understand at a glance.

### One File to Try

```swift
let web = io.web()

io.listen(9123, fun(req: Request) {
    match req.path {
        "/" => return web.page("<h1>Hello, QuickScript!</h1>"),
        "/ping" => return web.json("{\"ok\":true}"),
        other => return web.error.text(404, "Unknown route: " + other),
    }
})
```

That’s the whole server: typed request, typed responses, no frameworks.

### What to Expect

- Strong typing across control flow, options/results, objects/enums, and built-ins.
- Batteries for files, ranges, random, HTTP servers, and web response helpers.
- A bias for speed: zero-copy where safe, small runtime, LLVM-backed codegen.

### Learn More

This README stays short on purpose. The full language guide, examples, and deep dives live on the website. Check the docs there for syntax, standard library details, and deployment tips.

### See It for Yourself (perf)

- QuickScript beats Node on hot loops after the one-time Rust build: 20M sum loop runs in ~0.07s vs Node’s ~0.24s; 200M loop runs in ~0.34s vs Node’s ~0.53s on this machine.
- QuickScript sample:

```swift
let sum = 0;
let i = 0;
while i < 20000000 {
    sum = sum + i;
    i = i + 1;
}
print(sum.str());
```

- JavaScript sample:

```javascript
let sum = 0;
for (let i = 0; i < 20000000; i++) {
  sum += i;
}
console.log(sum);
```

- Run both (after the first `cargo run --release`, reuse the built binary for steady-state numbers):
  - `time target/release/quick bench/short.qx`
  - `time node bench/short.js`
- For a longer run that dwarfs startup, try:
  - `time target/release/quick bench/long.qx`
  - `time node bench/long.js`
- For a “startup is negligible” burn (~30s+), use the acrobatics benchmark (same math across languages):
  - `time target/release/quick bench/acrobatics.qx`
  - `time node bench/acrobatics.js`
  - `PATH="/opt/homebrew/opt/openjdk@21/bin:$PATH" time java -cp bench Acrobatics`
- For a shape-shifting object test that stresses dynamic runtimes:
  - `time target/release/quick bench/shape_shift.qx`
  - `time node bench/shape_shift.js`
  - `time python3 bench/shape_shift.py` (shorter iteration count to keep Python runtime reasonable)
