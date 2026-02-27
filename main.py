#!/usr/bin/env python3
"""
zip_crack.py
Usage:
    python3 zip_crack.py passwords.txt target.zip [options]

Features:
- Dictionary-based ZIP password checking (classic PKZIP)
- Multiprocessing (parallel workers)
- Checkpoint/resume support
- Optional total-counting of passwords (--count)
- Verbose/progress display (--verbose)
- Shows which process found the password and how many passwords were checked
"""
import argparse
import zipfile
import multiprocessing as mp
import sys
import os
from itertools import islice

# Globals for worker access
ZIP_PATH = None
TEST_MEMBER = None
FOUND_EVENT = None

def init_worker(zip_path, test_member, found_event):
    global ZIP_PATH, TEST_MEMBER, FOUND_EVENT
    ZIP_PATH = zip_path
    TEST_MEMBER = test_member
    FOUND_EVENT = found_event

def try_password(item):
    """
    Worker: try a single password tuple (index, password_str).
    Returns (password_str, index, pid) on success, else None.
    """
    if FOUND_EVENT.is_set():
        return None
    idx, pw = item
    pw_str = pw.rstrip("\n\r")
    if pw_str == "":
        return None
    for enc in ("utf-8", "latin-1"):
        try:
            pwb = pw_str.encode(enc)
        except Exception:
            continue
        try:
            with zipfile.ZipFile(ZIP_PATH, 'r') as zf:
                with zf.open(TEST_MEMBER, pwd=pwb) as f:
                    # read a small chunk to confirm
                    f.read(16)
            # success
            FOUND_EVENT.set()
            return (pw_str, idx, os.getpid())
        except (RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile, OSError):
            continue
    return None

def password_generator(path, start_line=0):
    """Yield (index, line) pairs starting at start_line (0-indexed)."""
    with open(path, 'r', errors='ignore') as fh:
        for i, line in enumerate(fh):
            if i < start_line:
                continue
            yield (i, line.rstrip("\n\r"))

def count_lines(path):
    """Count number of non-empty lines in file (fast streaming)."""
    cnt = 0
    with open(path, 'r', errors='ignore') as fh:
        for _ in fh:
            cnt += 1
    return cnt

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("passwords", help="Path to passwords.txt (one per line)")
    ap.add_argument("zipfile", help="Target zip file")
    ap.add_argument("--workers", type=int, default=max(1, mp.cpu_count() - 1),
                    help="Number of parallel processes (default: cpu_count-1)")
    ap.add_argument("--checkpoint", default="zip_crack.ckpt",
                    help="Checkpoint file to save progress (default: zip_crack.ckpt)")
    ap.add_argument("--save-interval", type=int, default=1000,
                    help="Save checkpoint every N attempts (default 1000)")
    ap.add_argument("--count", action="store_true",
                    help="Pre-count total passwords and display progress as X/Y")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Verbose: print progress messages")
    ap.add_argument("--progress-interval", type=int, default=1000,
                    help="How often to print progress (in number of attempts). Default 1000.")
    args = ap.parse_args()

    if not os.path.isfile(args.passwords):
        print("Passwords file not found:", args.passwords); sys.exit(1)
    if not os.path.isfile(args.zipfile):
        print("Zip file not found:", args.zipfile); sys.exit(1)

    # resume position
    start_line = 0
    if os.path.exists(args.checkpoint):
        try:
            with open(args.checkpoint, 'r') as cfh:
                start_line = int(cfh.read().strip())
                if args.verbose:
                    print(f"Resuming from line {start_line} (from {args.checkpoint})")
        except Exception:
            start_line = 0

    # pick a member inside the zip to test (first one)
    with zipfile.ZipFile(args.zipfile, 'r') as zf:
        namelist = zf.namelist()
        if not namelist:
            print("Zip archive has no files."); sys.exit(1)
        test_member = namelist[0]

    total = None
    if args.count:
        if args.verbose:
            print("Counting total passwords in file... (this may take a moment)")
        total = count_lines(args.passwords)
        if args.verbose:
            print(f"Total passwords in file: {total}")

    manager = mp.Manager()
    found_event = manager.Event()

    pool = mp.Pool(processes=args.workers,
                   initializer=init_worker,
                   initargs=(args.zipfile, test_member, found_event))

    attempts = start_line  # number of passwords *already* attempted before resume
    last_processed_index = start_line - 1

    try:
        gen = password_generator(args.passwords, start_line=start_line)
        it = gen  # yields (index, line)
        if args.verbose:
            print("Starting attack...")
        for result in pool.imap_unordered(try_password, it, chunksize=1):
            attempts += 1
            # result is None or (pw_str, idx, pid)
            if result:
                pw_str, idx, pid = result
                # compute checked count: if total known, show idx+1 and total; otherwise attempts
                checked = idx + 1
                if total is not None:
                    print(f"\n*** Password FOUND: {pw_str}")
                    print(f"Checked {checked}/{total} (line {idx}) — found by worker pid {pid}")
                else:
                    print(f"\n*** Password FOUND: {pw_str}")
                    print(f"Checked {checked} passwords (line {idx}) — found by worker pid {pid}")
                # write file
                try:
                    with open("zip_found.txt", "w") as fh:
                        fh.write(pw_str + "\n")
                except Exception:
                    pass
                found_event.set()
                # save checkpoint of found line
                try:
                    with open(args.checkpoint, 'w') as cfh:
                        cfh.write(str(idx))
                except Exception:
                    pass
                break

            # update last_processed_index if we can (pool returns in arbitrary order)
            # We'll approximate by attempts + start_line - 1 as progress toward resume checkpoint
            last_processed_index = start_line + attempts - 1

            # periodic checkpoint + verbose progress
            if attempts % args.save_interval == 0:
                try:
                    with open(args.checkpoint, 'w') as cfh:
                        cfh.write(str(last_processed_index))
                except Exception:
                    pass
                if args.verbose:
                    if total:
                        print(f"[checkpoint] saved at line {last_processed_index} — checked ~{attempts}/{total}")
                    else:
                        print(f"[checkpoint] saved at line {last_processed_index} — checked ~{attempts}")

            # more frequent progress prints (user-facing)
            if args.verbose and (attempts % args.progress_interval == 0):
                if total is not None:
                    print(f"[progress] checked ~{attempts}/{total} passwords")
                else:
                    print(f"[progress] checked ~{attempts} passwords")

            if found_event.is_set():
                break

        if not found_event.is_set():
            print("Password not found in provided list.")
    except KeyboardInterrupt:
        print("\nInterrupted by user. Saving checkpoint at attempts =", attempts)
        try:
            with open(args.checkpoint, 'w') as cfh:
                cfh.write(str(last_processed_index))
        except Exception:
            pass
    finally:
        pool.terminate()
        pool.join()

if __name__ == "__main__":
    main()
