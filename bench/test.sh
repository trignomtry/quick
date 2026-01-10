#!/bin/bash

# Exit on error
set -e

# --- Configuration ---
# Path to the QuickScript executable
# Assumes the script is run from the project root
QUICK_EXECUTABLE="./target/release/quick"

# Benchmark files
LOOP_BENCH_QS="bench/loop.qx"
LOOP_BENCH_JS="bench/loop.js"
FIB_BENCH_QS="bench/fib.qx"
FIB_BENCH_JS="bench/fib.js"
LONG_BENCH_QS="bench/long_test.qx"
LONG_BENCH_JS="bench/long_test.js"

# --- Helper Functions ---
print_header() {
    echo "========================================"
    echo "$1"
    echo "========================================"
}

# --- Build ---
print_header "Building QuickScript executable"
RUSTFLAGS="-Awarnings" cargo build --release
echo "Build complete."
echo ""

# --- Warm-up ---
# Run the executable once to handle macOS Gatekeeper verification
# so it doesn't interfere with the benchmark timings.
print_header "Warming up QuickScript executable"
$QUICK_EXECUTABLE bench/warmup.qx
echo "Warm-up complete."
echo ""


# --- Benchmarks ---

# Loop Benchmark
print_header "Benchmark: Loop Summation"
echo "Running QuickScript loop..."
time $QUICK_EXECUTABLE $LOOP_BENCH_QS
echo ""
echo "Running JavaScript loop..."
time node $LOOP_BENCH_JS
echo ""

# Fibonacci Benchmark
print_header "Benchmark: Recursive Fibonacci"
echo "Running QuickScript Fibonacci (JIT)..."
time $QUICK_EXECUTABLE $FIB_BENCH_QS
echo ""

echo "Building QuickScript Fibonacci (AOT)..."
$QUICK_EXECUTABLE build $FIB_BENCH_QS
echo "AOT build complete."
echo ""

echo "Warming up AOT executable..."
./build/program > /dev/null
echo "Warm-up complete."
echo ""

echo "Running QuickScript Fibonacci (AOT)..."
time ./build/program
echo ""

echo "Running JavaScript Fibonacci..."
time node $FIB_BENCH_JS
echo ""

# Long Test Benchmark
print_header "Benchmark: Long Test (Looping Fibonacci)"
echo "Running QuickScript Long Test..."
time $QUICK_EXECUTABLE $LONG_BENCH_QS
echo ""
echo "Running JavaScript Long Test..."
time node $LONG_BENCH_JS
echo ""

print_header "Benchmark suite complete."
