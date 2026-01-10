
function fib(n) {
    if (n <= 1) {
        return n;
    }
    return fib(n - 2) + fib(n - 1);
}

let total = 0;
for (let i = 0; i < 20; i++) {
    total = total + fib(i);
}

console.log("JavaScript Long Test Total: " + total);
