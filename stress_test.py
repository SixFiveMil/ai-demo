"""
Open WebUI Concurrent Session Stress Tester
============================================
Simulates multiple students sending prompts to Open WebUI simultaneously.
Measures response times, queue depth behavior, and failure thresholds.

Usage:
    python stress_test.py                        # Default: ramp from 1 to 20 sessions
    python stress_test.py --url http://IP:3000   # Custom Open WebUI URL
    python stress_test.py --max-users 30         # Test up to 30 concurrent users
    python stress_test.py --fixed 10             # Hold exactly 10 concurrent users
    python stress_test.py --model hardened_bot   # Test a specific model
    python stress_test.py --no-auth              # Skip if Open WebUI has no login

Requirements:
    pip install requests
"""

import argparse
import concurrent.futures
import json
import statistics
import sys
import time
from datetime import datetime

try:
    import requests
except ImportError:
    print("Missing 'requests' library. Run: pip install requests")
    sys.exit(1)


# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------

DEFAULT_URL   = "http://localhost:3000"
DEFAULT_MODEL = "hardened_bot"

# Realistic student prompts — varied length and complexity to simulate real lab traffic
STUDENT_PROMPTS = [
    "What is prompt injection and why is it dangerous?",
    "Explain the difference between Phase 1 and Phase 2 in this demo.",
    "Why can't we just use a strong system prompt to protect the AI?",
    "What is the gateway filtering and how does it work?",
    "Can you give me an example of a jailbreak attack?",
    "What does the egress filter check for?",
    "Why does the fictional framing bypass the hardened model?",
    "What would happen if someone tried a base64 encoded attack?",
    "How does the DAN persona attack work?",
    "What is defense in depth and how does it apply to AI systems?",
]


# ---------------------------------------------------------------------------
# OPEN WEBUI API HELPERS
# ---------------------------------------------------------------------------

def get_auth_token(base_url: str, email: str, password: str) -> str | None:
    """Authenticate with Open WebUI and return a bearer token."""
    try:
        r = requests.post(
            f"{base_url}/api/v1/auths/signin",
            json={"email": email, "password": password},
            timeout=10
        )
        if r.status_code == 200:
            return r.json().get("token")
        print(f"  ⚠️  Auth failed: {r.status_code} — {r.text[:100]}")
        return None
    except Exception as e:
        print(f"  ⚠️  Auth error: {e}")
        return None


def send_chat_message(base_url: str, model: str, prompt: str, token: str | None) -> dict:
    """
    Send a single chat completion request to Open WebUI's OpenAI-compatible endpoint.
    Returns timing and result metadata.
    """
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "stream": False,
    }

    start = time.time()
    result = {
        "prompt_preview": prompt[:50],
        "success": False,
        "status_code": None,
        "response_time_s": None,
        "response_preview": None,
        "error": None,
    }

    try:
        r = requests.post(
            f"{base_url}/api/v1/chat/completions",
            headers=headers,
            json=payload,
            timeout=120  # 2 min timeout — inference can be slow under load
        )
        elapsed = time.time() - start
        result["status_code"] = r.status_code
        result["response_time_s"] = round(elapsed, 2)

        if r.status_code == 200:
            content = r.json()["choices"][0]["message"]["content"]
            result["success"] = True
            result["response_preview"] = content[:80].replace("\n", " ")
        else:
            result["error"] = f"HTTP {r.status_code}: {r.text[:100]}"

    except requests.exceptions.Timeout:
        result["response_time_s"] = round(time.time() - start, 2)
        result["error"] = "Timeout (>120s)"
    except Exception as e:
        result["response_time_s"] = round(time.time() - start, 2)
        result["error"] = str(e)

    return result


# ---------------------------------------------------------------------------
# STRESS TEST RUNNERS
# ---------------------------------------------------------------------------

def run_concurrent_batch(base_url: str, model: str, token: str | None,
                         num_users: int, prompts: list) -> list:
    """
    Fire `num_users` requests simultaneously and collect results.
    Each simulated student gets a different prompt cycling through the list.
    """
    tasks = []
    for i in range(num_users):
        prompt = prompts[i % len(prompts)]
        tasks.append((base_url, model, prompt, token))

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_users) as executor:
        futures = [executor.submit(send_chat_message, *t) for t in tasks]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    return results


def print_batch_summary(num_users: int, results: list):
    """Print a one-line summary for a concurrent batch."""
    successes   = [r for r in results if r["success"]]
    failures    = [r for r in results if not r["success"]]
    times       = [r["response_time_s"] for r in results if r["response_time_s"]]

    avg_time    = round(statistics.mean(times), 2) if times else "—"
    max_time    = round(max(times), 2) if times else "—"
    min_time    = round(min(times), 2) if times else "—"

    status = "✅" if len(failures) == 0 else ("⚠️ " if len(successes) > 0 else "❌")

    print(
        f"  {status}  {num_users:>3} users │ "
        f"Success: {len(successes)}/{num_users} │ "
        f"Avg: {avg_time}s │ "
        f"Min: {min_time}s │ "
        f"Max: {max_time}s"
        + (f" │ Errors: {len(failures)}" if failures else "")
    )

    # Surface any error types
    for r in failures:
        print(f"         └─ ⚠️  {r['error']}")

    return len(failures) == 0, avg_time, max_time


def run_ramp_test(base_url: str, model: str, token: str | None,
                  max_users: int, step: int, prompts: list,
                  acceptable_avg_s: float, acceptable_max_s: float):
    """
    Ramp test: start at 1 user, increase by `step` each round,
    stop at `max_users` or when thresholds are breached.
    """
    print(f"\n{'='*72}")
    print(f"  🚀  RAMP TEST — 1 to {max_users} concurrent users (step: {step})")
    print(f"  Target: avg response < {acceptable_avg_s}s, max response < {acceptable_max_s}s")
    print(f"  Model: {model}  │  URL: {base_url}")
    print(f"{'='*72}")
    print(f"  {'Users':>5}  {'Success':>10}  {'Avg (s)':>9}  {'Min (s)':>9}  {'Max (s)':>9}  Notes")
    print(f"  {'-'*65}")

    all_ok = True
    breaking_point = None

    for n in range(1, max_users + 1, step):
        results = run_concurrent_batch(base_url, model, token, n, prompts)
        successes = [r for r in results if r["success"]]
        times     = [r["response_time_s"] for r in results if r["response_time_s"]]

        avg = round(statistics.mean(times), 2) if times else 999
        mx  = round(max(times), 2) if times else 999
        mn  = round(min(times), 2) if times else 999

        notes = []
        if avg > acceptable_avg_s: notes.append(f"⚠️ avg>{acceptable_avg_s}s")
        if mx > acceptable_max_s:  notes.append(f"⚠️ max>{acceptable_max_s}s")
        if len(successes) < n:     notes.append(f"❌ {n - len(successes)} failed")

        status = "✅" if not notes else ("❌" if len(successes) == 0 else "⚠️ ")
        note_str = "  ".join(notes) if notes else "OK"

        print(
            f"  {status}  {n:>3}    │  {len(successes)}/{n:>2}      │  "
            f"{avg:>7}  │  {mn:>7}  │  {mx:>7}  │  {note_str}"
        )

        if notes and breaking_point is None:
            breaking_point = n

        # Small pause between ramp steps to let the server breathe
        time.sleep(2)

    print(f"\n{'='*72}")
    if breaking_point:
        print(f"  📊  Degradation detected at {breaking_point} concurrent users.")
        print(f"      Comfortable capacity estimate: {max(1, breaking_point - step)} simultaneous students.")
    else:
        print(f"  📊  All {max_users} concurrent users completed within thresholds.")
        print(f"      Consider re-running with --max-users {max_users + 10} to find the ceiling.")
    print(f"{'='*72}\n")


def run_fixed_test(base_url: str, model: str, token: str | None,
                   num_users: int, rounds: int, prompts: list):
    """
    Fixed load test: hold exactly `num_users` concurrent users for `rounds` rounds.
    Good for sustained load measurement once you know roughly where the ceiling is.
    """
    print(f"\n{'='*72}")
    print(f"  🔁  FIXED LOAD TEST — {num_users} concurrent users × {rounds} rounds")
    print(f"  Model: {model}  │  URL: {base_url}")
    print(f"{'='*72}")

    all_times = []
    all_errors = 0

    for i in range(1, rounds + 1):
        print(f"\n  Round {i}/{rounds}:")
        results = run_concurrent_batch(base_url, model, token, num_users, prompts)
        ok, avg, mx = print_batch_summary(num_users, results)
        times = [r["response_time_s"] for r in results if r["response_time_s"]]
        all_times.extend(times)
        all_errors += sum(1 for r in results if not r["success"])
        time.sleep(3)

    print(f"\n{'='*72}")
    print(f"  📊  Aggregate over {rounds} rounds at {num_users} users:")
    print(f"      Overall avg:    {round(statistics.mean(all_times), 2)}s")
    print(f"      Overall median: {round(statistics.median(all_times), 2)}s")
    print(f"      Overall max:    {round(max(all_times), 2)}s")
    print(f"      Total errors:   {all_errors}/{num_users * rounds} requests")
    if all_times:
        p95 = sorted(all_times)[int(len(all_times) * 0.95)]
        print(f"      P95 latency:    {round(p95, 2)}s  (95% of students waited ≤ this long)")
    print(f"{'='*72}\n")


# ---------------------------------------------------------------------------
# CONNECTIVITY CHECK
# ---------------------------------------------------------------------------

def check_connectivity(base_url: str, token: str | None) -> bool:
    """Quick sanity check before starting the load test."""
    print(f"\n  Checking connectivity to {base_url}...")
    try:
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        r = requests.get(f"{base_url}/api/models", headers=headers, timeout=10)
        if r.status_code == 200:
            models = [m["id"] for m in r.json().get("data", [])]
            print(f"  ✅  Connected. Available models: {', '.join(models) if models else 'none listed'}")
            return True
        else:
            print(f"  ❌  Connected but got HTTP {r.status_code}. Check auth or URL.")
            return False
    except Exception as e:
        print(f"  ❌  Cannot reach {base_url}: {e}")
        print(f"      Make sure Open WebUI is running and accessible.")
        return False


# ---------------------------------------------------------------------------
# ENTRY POINT
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Open WebUI Concurrent Session Stress Tester"
    )
    parser.add_argument("--url",        default=DEFAULT_URL,   help=f"Open WebUI base URL (default: {DEFAULT_URL})")
    parser.add_argument("--model",      default=DEFAULT_MODEL, help=f"Model to test (default: {DEFAULT_MODEL})")
    parser.add_argument("--max-users",  type=int, default=20,  help="Max concurrent users for ramp test (default: 20)")
    parser.add_argument("--step",       type=int, default=2,   help="User increment per ramp step (default: 2)")
    parser.add_argument("--fixed",      type=int, default=None,help="Run fixed load test at this many users instead of ramping")
    parser.add_argument("--rounds",     type=int, default=3,   help="Rounds for fixed load test (default: 3)")
    parser.add_argument("--avg-limit",  type=float, default=30.0, help="Acceptable avg response time in seconds (default: 30)")
    parser.add_argument("--max-limit",  type=float, default=60.0, help="Acceptable max response time in seconds (default: 60)")
    parser.add_argument("--email",      default="admin@localhost.com", help="Open WebUI login email")
    parser.add_argument("--password",   default="admin",              help="Open WebUI login password")
    parser.add_argument("--no-auth",    action="store_true",          help="Skip authentication (if Open WebUI has no login)")
    args = parser.parse_args()

    print(f"\n{'='*72}")
    print(f"  🛡️  Open WebUI Stress Tester")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*72}")

    # Auth
    token = None
    if not args.no_auth:
        print(f"\n  Authenticating as {args.email}...")
        token = get_auth_token(args.url, args.email, args.password)
        if token:
            print(f"  ✅  Auth token acquired.")
        else:
            print(f"  ⚠️  Auth failed — retrying without token (may fail if auth is required).")
            print(f"      Use --email / --password to set credentials, or --no-auth to skip.")

    # Connectivity check
    if not check_connectivity(args.url, token):
        sys.exit(1)

    # Run the appropriate test mode
    if args.fixed:
        run_fixed_test(
            base_url=args.url,
            model=args.model,
            token=token,
            num_users=args.fixed,
            rounds=args.rounds,
            prompts=STUDENT_PROMPTS,
        )
    else:
        run_ramp_test(
            base_url=args.url,
            model=args.model,
            token=token,
            max_users=args.max_users,
            step=args.step,
            prompts=STUDENT_PROMPTS,
            acceptable_avg_s=args.avg_limit,
            acceptable_max_s=args.max_limit,
        )


if __name__ == "__main__":
    main()