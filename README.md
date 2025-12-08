# QuickScript

QuickScript is a small, strongly typed scripting language that JITs to native code. The goal is a predictable surface: async I/O, HTTP helpers, ranges, JSON, and typed objects without giving up compile-time guarantees. Performance should be “compiled-fast”, the API should stay tiny, and new features must extend existing patterns instead of adding surprises.

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
