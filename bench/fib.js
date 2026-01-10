function fib(n) {
  if (n <= 1) {
    return n;
  }
  return fib(n - 2) + fib(n - 1);
}

let n = 38;
console.log("JavaScript Fib(" + n + "): " + fib(n));
