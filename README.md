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
