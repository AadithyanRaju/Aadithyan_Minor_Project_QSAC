#!/usr/bin/env python3
"""
QSAC Benchmark Harness
======================

Reads cycle-count and test results from the device over UART,
following the pqm4 speed.c / benchmarks.py pattern.

Usage:
    python benchmarks.py --port /dev/ttyACM0 --baud 115200 --test kat --algo mlkem512
    python benchmarks.py --port /dev/ttyACM0 --baud 115200 --test speed --algo all
    python benchmarks.py --port /dev/ttyACM0 --baud 115200 --test negative --suite all

Output: CSV and human-readable tables of results.
"""

import argparse
import csv
import sys
import time
from dataclasses import dataclass, field
from typing import Optional

# TODO Phase 1: Uncomment when pyserial is available
# import serial


@dataclass
class BenchmarkResult:
    """Stores timing results for a single crypto operation."""
    algorithm: str
    operation: str
    cycles: list[int] = field(default_factory=list)
    stack_bytes: Optional[int] = None

    @property
    def count(self) -> int:
        return len(self.cycles)

    @property
    def mean(self) -> float:
        return sum(self.cycles) / len(self.cycles) if self.cycles else 0

    @property
    def min_val(self) -> int:
        return min(self.cycles) if self.cycles else 0

    @property
    def max_val(self) -> int:
        return max(self.cycles) if self.cycles else 0

    @property
    def latency_ms(self) -> float:
        """Estimated latency at 80 MHz."""
        return self.mean / 80_000_000 * 1000


def parse_args():
    parser = argparse.ArgumentParser(description="QSAC Benchmark Harness")
    parser.add_argument("--port", default="/dev/ttyACM0",
                        help="Serial port (default: /dev/ttyACM0)")
    parser.add_argument("--baud", type=int, default=115200,
                        help="Baud rate (default: 115200)")
    parser.add_argument("--test", choices=["kat", "speed", "negative"],
                        required=True, help="Test type to run")
    parser.add_argument("--algo", default="all",
                        help="Algorithm to test: mlkem512, mldsa2, all")
    parser.add_argument("--suite", default="all",
                        help="Negative test suite: replay, forge, corrupt, all")
    parser.add_argument("--iterations", type=int, default=500,
                        help="Number of iterations for speed tests (default: 500)")
    parser.add_argument("--output", default=None,
                        help="Output CSV file (default: stdout)")
    return parser.parse_args()


def connect_serial(port: str, baud: int):
    """Open a serial connection to the target device."""
    # TODO Phase 1: Implement serial connection
    # return serial.Serial(port, baud, timeout=5)
    print(f"[STUB] Would connect to {port} at {baud} baud")
    return None


def send_command(ser, cmd: str) -> list[str]:
    """Send a command to the device and collect response lines."""
    # TODO Phase 1: Implement command/response protocol
    # ser.write(f"{cmd}\n".encode())
    # lines = []
    # while True:
    #     line = ser.readline().decode().strip()
    #     if line == "END":
    #         break
    #     lines.append(line)
    # return lines
    print(f"[STUB] Would send command: {cmd}")
    return []


def run_kat_test(ser, algo: str):
    """Run Known-Answer-Test vectors for the specified algorithm."""
    print(f"\n{'='*50}")
    print(f"  KAT Test: {algo}")
    print(f"{'='*50}")

    # TODO Phase 3: Send KAT test command and parse results
    # response = send_command(ser, f"KAT {algo}")
    # parse pass/fail from response
    print("[STUB] KAT test not yet implemented — requires Phase 3 PQC integration")


def run_speed_test(ser, algo: str, iterations: int) -> list[BenchmarkResult]:
    """Run speed benchmarks and collect cycle counts."""
    results = []
    print(f"\n{'='*50}")
    print(f"  Speed Test: {algo} ({iterations} iterations)")
    print(f"{'='*50}")

    # TODO Phase 6: Send speed test commands, parse cycle counts
    # operations = {
    #     "mlkem512": ["KeyGen", "Encaps", "Decaps"],
    #     "mldsa2":   ["KeyGen", "Sign", "Verify"],
    # }
    # for op in operations.get(algo, []):
    #     response = send_command(ser, f"SPEED {algo} {op} {iterations}")
    #     result = BenchmarkResult(algorithm=algo, operation=op)
    #     for line in response:
    #         if line.startswith("CYCLES:"):
    #             result.cycles.append(int(line.split(":")[1]))
    #         elif line.startswith("STACK:"):
    #             result.stack_bytes = int(line.split(":")[1])
    #     results.append(result)

    print("[STUB] Speed test not yet implemented — requires Phase 6")
    return results


def print_results_table(results: list[BenchmarkResult]):
    """Print a formatted results table."""
    if not results:
        return

    print(f"\n{'Algorithm':<15} {'Operation':<12} {'Min':>10} {'Mean':>10} "
          f"{'Max':>10} {'Latency':>10} {'Stack':>8}")
    print("-" * 80)
    for r in results:
        print(f"{r.algorithm:<15} {r.operation:<12} {r.min_val:>10,} "
              f"{r.mean:>10,.0f} {r.max_val:>10,} "
              f"{r.latency_ms:>9.2f}ms {r.stack_bytes or 'N/A':>8}")


def export_csv(results: list[BenchmarkResult], filename: str):
    """Export results to CSV."""
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Algorithm", "Operation", "Min Cycles", "Mean Cycles",
                         "Max Cycles", "Latency (ms)", "Stack (bytes)", "Iterations"])
        for r in results:
            writer.writerow([r.algorithm, r.operation, r.min_val, f"{r.mean:.0f}",
                             r.max_val, f"{r.latency_ms:.2f}",
                             r.stack_bytes or "", r.count])
    print(f"\nResults exported to {filename}")


def main():
    args = parse_args()

    print("QSAC Benchmark Harness v0.1")
    print(f"Port: {args.port}, Baud: {args.baud}")
    print(f"Test: {args.test}, Algorithm: {args.algo}")

    ser = connect_serial(args.port, args.baud)

    if args.test == "kat":
        algos = ["mlkem512", "mldsa2"] if args.algo == "all" else [args.algo]
        for algo in algos:
            run_kat_test(ser, algo)

    elif args.test == "speed":
        algos = ["mlkem512", "mldsa2"] if args.algo == "all" else [args.algo]
        all_results = []
        for algo in algos:
            results = run_speed_test(ser, algo, args.iterations)
            all_results.extend(results)
        print_results_table(all_results)
        if args.output:
            export_csv(all_results, args.output)

    elif args.test == "negative":
        # TODO Phase 5: Implement negative/adversarial tests
        print("\n[STUB] Negative tests not yet implemented — requires Phase 5")

    # if ser:
    #     ser.close()


if __name__ == "__main__":
    main()
