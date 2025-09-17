#!/usr/bin/env python3
"""
Optimized streaming fetch for Vision One ASRM vulnerableDevices.

- Streams items directly to disk (compact while writing).
- After completion, re-opens the file and runs it through Python's json.tool, so the final result is pretty-formatted (like `jq .`).
- Logging shows pages, counts, and elapsed time.
"""

import os
import sys
import time
import json
from datetime import datetime
from typing import Dict, Any, Optional

import requests

try:
    import orjson
    def dumps_bytes(obj) -> bytes:
        return orjson.dumps(obj)  # fast compact
except ImportError:
    def dumps_bytes(obj) -> bytes:
        return json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode("utf-8")

BASE_URL = "https://api.xdr.trendmicro.com/v3.0/asrm/vulnerableDevices"
TOKEN = os.getenv("TM_API_TOKEN") or "<API key here>"
# API only supports specific enum values for 'top': 10, 50, 100, 200 (200 is maximum)
PAGE_SIZE = int(os.getenv("PAGE_SIZE", "200"))
LOG_EVERY = int(os.getenv("LOG_EVERY", "5"))
TIMEOUT_SECS = 20
MAX_RETRIES = 5
BACKOFF_BASE = 1.5
# Skip pretty-printing for faster completion (set to 'false' to enable pretty-printing)
COMPACT_OUTPUT = os.getenv("COMPACT_OUTPUT", "true").lower() == "true"

def _auth_header() -> str:
    if not TOKEN or TOKEN.strip() == "<PUT_YOUR_BEARER_TOKEN_HERE>":
        print("ERROR: Set TM_API_TOKEN or fill placeholder.", file=sys.stderr)
        sys.exit(1)
    return f"Bearer {TOKEN}"

def _fmt_secs(s: float) -> str:
    if s < 60:
        return f"{s:.1f}s"
    m, sec = divmod(int(s), 60)
    if m < 60:
        return f"{m}m{sec:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m{sec:02d}s"

def _session() -> requests.Session:
    s = requests.Session()
    # Optimize connection pool for better reuse and performance
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=50,    # Increased for better connection reuse
        pool_maxsize=50,        # Match pool_connections
        max_retries=0
    )
    s.mount("https://", adapter)
    s.headers.update({
        "Accept": "application/json",
        "Authorization": _auth_header(),
        "Accept-Encoding": "gzip, deflate, br",  # Add brotli compression
        "Connection": "keep-alive",
        "User-Agent": "VisionOne-DeviceVuln-Fetcher/1.0",  # Better identification
    })
    return s

def fetch_page(session: requests.Session, url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    attempt = 0
    while True:
        try:
            # Use stream=True for large responses to avoid loading everything into memory at once
            resp = session.get(url, params=params, timeout=TIMEOUT_SECS, stream=True)
        except requests.RequestException as e:
            attempt += 1
            if attempt > MAX_RETRIES:
                raise
            sleep_s = (BACKOFF_BASE ** attempt)
            print(f"Request error ({e.__class__.__name__}), retry {attempt}/{MAX_RETRIES} after {sleep_s:.1f}s...")
            time.sleep(sleep_s)
            continue

        if resp.status_code == 200:
            # For JSON responses, we still need to load the full response
            # but this allows for better memory management for very large responses
            return resp.json()

        if resp.status_code in (429, 500, 502, 503, 504):
            attempt += 1
            if attempt > MAX_RETRIES:
                resp.raise_for_status()
            retry_after = resp.headers.get("Retry-After")
            try:
                sleep_s = float(retry_after) if retry_after else (BACKOFF_BASE ** attempt)
            except ValueError:
                sleep_s = (BACKOFF_BASE ** attempt)
            print(f"HTTP {resp.status_code}, retry {attempt}/{MAX_RETRIES} after {sleep_s:.1f}s...")
            time.sleep(sleep_s)
            continue

        resp.raise_for_status()

def stream_all() -> str:
    session = _session()
    ts_local = datetime.now().strftime("%Y%m%d_%H%M")
    out_path = f"vulnerable_devices_{ts_local}.json"

    url = BASE_URL
    params: Dict[str, Any] = {"top": PAGE_SIZE}

    pages = 0
    items_total = 0
    start_ts = time.time()

    print(f"Start: {BASE_URL}  (top={PAGE_SIZE})   out={out_path}")

    # Increase buffer size for better I/O performance with large datasets
    with open(out_path, "wb", buffering=4*1024*1024) as f:  # 4MB buffer
        f.write(b"[\n")
        first_item = True

        while True:
            data = fetch_page(session, url, params=params)
            pages += 1

            page_items = data.get("items", [])
            for item in page_items:
                if not first_item:
                    f.write(b",\n")
                f.write(dumps_bytes(item))
                first_item = False
            items_total += len(page_items)

            elapsed = time.time() - start_ts
            if pages % LOG_EVERY == 0 or pages == 1:
                rate = items_total / elapsed if elapsed > 0 else 0
                print(f"[Page {pages}] +{len(page_items)} items  total={items_total}  elapsed={_fmt_secs(elapsed)}  rate={rate:.1f} items/sec")

            next_link = data.get("nextLink")
            if not next_link:
                api_total = data.get("totalCount", 'n/a')
                print(f"Done. pages={pages} totalItems={items_total} apiTotal={api_total} elapsed={_fmt_secs(elapsed)}")
                break

            url = next_link
            params = None

        f.write(b"\n]\n")

    # Optional pretty-printing (can be disabled for performance)
    if not COMPACT_OUTPUT:
        print("Reformatting JSON (pretty print)...")
        try:
            with open(out_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"WARNING: could not reformat JSON ({e}), keeping compact output.")
    else:
        print("Skipping pretty-print for performance (set COMPACT_OUTPUT=false to enable)")

    return out_path

def main():
    try:
        out_path = stream_all()
    except Exception as e:
        print(f"Failed: {e}", file=sys.stderr)
        sys.exit(2)
    print(f"Wrote: {out_path}")

if __name__ == "__main__":
    main()