from __future__ import annotations
from pathlib import Path
from tqdm import tqdm
import sys

def scan_utf8_with_progress(
    src_path: str,
    bad_suffix: str = ".nbadhex",
    print_ok: bool = False,
    max_print: int | None = None,
    flush_every: int = 10000,
):
    src = Path(src_path)
    total_bytes = src.stat().st_size
    bad_path = src.with_name(src.name + bad_suffix)

    total_lines = ok = bad = 0
    printed = 0

    with open(src, "rb") as fin, \
         open(bad_path, "w", encoding="ascii", newline="\n") as fb, \
         tqdm(
             total=total_bytes,
             unit="B",
             unit_scale=True,
             unit_divisor=1024,
             desc="Scanning",
             smoothing=0.1,
         ) as pbar:

        fb.write("# lineno\tbad_pos\traw_len\traw_hex\n")

        for lineno, raw in enumerate(fin, 1):
            total_lines += 1
            pbar.update(len(raw))  # 按字节推进进度条

            raw = raw.rstrip(b"\r\n")

            try:
                s = raw.decode("utf-8", "strict")
                ok += 1
                if print_ok:
                    print(s)
                    printed += 1
                    if max_print and printed >= max_print:
                        print("[printing stopped, continue scanning...]", file=sys.stderr)
                        print_ok = False

            except UnicodeDecodeError as e:
                bad += 1
                fb.write(
                    f"{lineno}\t{e.start}\t{len(raw)}\t{raw.hex()}\n"
                )

            if total_lines % flush_every == 0:
                fb.flush()

    print(
        f"\nDone: lines={total_lines}, utf8_ok={ok}, bad={bad}\n"
        f"Bad hex saved to: {bad_path}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    scan_utf8_with_progress(
        src_path=r"password\PASSWORD.lst",
        bad_suffix=".nbadhex",
        print_ok=False,     # 15GB 文件强烈建议关掉
        max_print=200,
    )
