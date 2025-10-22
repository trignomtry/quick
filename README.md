# QuickScript

_Fast. Safe. Effortless._

QuickScript is a modern language that runs like compiled code and feels like a script.
You don’t tune it. You just write — it handles the rest.
The toolchain keeps the surface area tight: strong typing across control flow, predictable runtimes, and fast-running code. It feels like magic.

## Hello, World (and Server)

```swift
let web = io.web()

io.listen(9123, fun(req: Request) {
    match req.path {
        "/" => return web.page("<h1>Hello, world!</h1>"),
        "/static" => return web.file("test/index.html"),
        other => return web.error.page(404, "<h1>404: " + other + "</h1>"),
    }
})
```

No frameworks. No dependencies. Just QuickScript.

`Request` is a typed object with `method`, `path`, `query`, `headers`, and `body: Maybe(Str)`, so handlers stay predictable even as logic grows.

## Simple Logic

```swift
let name = "QuickScript"

if name == "QuickScript" {
    print("Hi there!")
}

for i in io.range().from(1).to(3) {
    print(i)
}

let odds = io.range().to(10).step(2)
for o in odds {
    print(o)
}
```

Readable. Instant. No wasted motion.

## Real Data

```swift
object User {
    name: Str,
    things: [Num],
    sessions: Obj(Bool)
}

let user = User {
    name: "John",
    things: [1, 2, 3],
    sessions: Obj.new()
}

user.sessions.insert("guest", true)

let guest = user.sessions.get("guest")
if guest.default(false) {
    print("Guest mode enabled")
}
```

`Obj.new()` builds a typed string-key map. `get(key)` returns a `Maybe`, keeping lookups safe without runtime casts.

## Safe by Design

```swift
enum Thing { Alpha, Sigma }

match Thing.Alpha {
    Thing.Alpha => print("Alpha mode"),
    Thing.Sigma => print("Sigma mode"),
}

maybe guest {
    print("Welcome back, " + guest)
} else {
    print("Nothing to unwrap")
}
```

Exhaustive matching. `maybe` handles options without losing static guarantees.

## Typed Web Helpers

```swift
let web = io.web()

if req.path == "/json" {
    return web.json("{\"message\": \"Hello!\"}")
}

if req.path == "/redirect" {
    return web.redirect("/", true)
}

return web.error.text(404, "Unknown route: " + req.path)
```

`io.web()` exposes typed helpers for text, HTML pages, static files, JSON bodies, redirects, and rich error responses (`web.error.text`, `.page`). Every method is checked before codegen so handlers can’t return the wrong shape.

## The io Library

The `io` module is built-in and always available. It covers standard input/output, file operations, randomness, ranges, and web utilities — all strongly typed, most backed by powerful runtimes.

```swift
let name = io.input("What's your name? ") // blocking read from stdin
io.write("greeting.txt", "Hello, " + name)

let text = io.read("greeting.txt").default("Couldn't read file!")
print(text)

print(io.random()) // number < 1
```

`io.read` and `io.write` are super fast for reading and writing files, use `io.input` to collect user input. `io.range()` builds numeric sequences that power `for` loops through `.from`, `.to`, and `.step`.

## Getting Started

1. Download the CLI from [Releases](#).
2. Run your first file:

   ```bash
   quick run main.qx
   ```

3. Watch it fly.

QuickScript loves beginners, rewards experts, and surprises everyone else.
Try it once. You’ll feel the speed before you finish typing.
