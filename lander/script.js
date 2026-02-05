// Code examples data
const examples = {
  hello: {
    filename: "hello.qx",
    code: 'print("Hello, World!")',
  },
  server: {
    filename: "server.qx",
    code: `let web = io.web();

io.listen(8080, fun(req: Request) {
    return web.file("./public" + req.path);
})`,
  },
  fibonacci: {
    filename: "fibonacci.qx",
    code: `fun fib(n: Num) {
    if n <= 1 {
        return n;
    }
    let first: Num = fib(n - 2);
    let second: Num = fib(n - 1);
    return first + second;
}

let n = 38;
print("QuickScript Fib(" + n.str() + "): " + fib(n).str());`,
  },
  loop: {
    filename: "loop.qx",
    code: `let total = 0;
let start = 0;
let end = 10000000;

for i in io.range().from(start).to(end) {
    total = total + i;
}

print("QuickScript Loop Total: " + total.str());`,
  },
  api: {
    filename: "api.qx",
    code: `let web = io.web();

io.listen(8087, fun(req: Request) {
  match req.path {
    "/hello" => return web.text("Hello, User!"),
    "/json" => return web.json("{\"data\": \"Hello, World!\"}"),
    path => return web.error.file(404, "404.html"),
  }
})`,
  },
};

// Example tabs functionality
document.addEventListener("DOMContentLoaded", function () {
  const tabs = document.querySelectorAll(".example-tab");
  const codeElement = document.getElementById("example-code");
  const filenameElement = document.getElementById("example-filename");

  tabs.forEach((tab) => {
    tab.addEventListener("click", function () {
      // Remove active class from all tabs
      tabs.forEach((t) => t.classList.remove("active"));
      // Add active class to clicked tab
      this.classList.add("active");

      // Update code display
      const exampleId = this.getAttribute("data-example");
      const example = examples[exampleId];

      if (example && codeElement && filenameElement) {
        codeElement.textContent = example.code;
        filenameElement.textContent = example.filename;
      }
    });
  });
});

// Docs page functionality
document.addEventListener("DOMContentLoaded", function () {
  const sidebarLinks = document.querySelectorAll(".sidebar-link");
  const docsSections = document.querySelectorAll(".docs-section");
  const mobileMenuBtn = document.getElementById("mobile-menu-btn");
  const sidebar = document.querySelector(".docs-sidebar");

  // Sidebar navigation
  sidebarLinks.forEach((link) => {
    link.addEventListener("click", function () {
      const sectionId = this.getAttribute("data-section");

      // Update active states
      sidebarLinks.forEach((l) => l.classList.remove("active"));
      this.classList.add("active");

      // Show corresponding section
      docsSections.forEach((section) => {
        section.classList.remove("active");
        if (section.id === sectionId) {
          section.classList.add("active");
        }
      });

      // Close mobile menu
      if (sidebar) {
        sidebar.classList.remove("mobile-open");
      }
    });
  });

  // Mobile menu toggle
  if (mobileMenuBtn && sidebar) {
    mobileMenuBtn.addEventListener("click", function () {
      sidebar.classList.toggle("mobile-open");
    });
  }
});
