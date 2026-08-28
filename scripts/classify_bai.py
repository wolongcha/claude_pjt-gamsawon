#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""감사원 감사결과 전문에서 정보화/정보시스템 관련 감사사항을 가려낸다.

감사보고서 전문 PDF의 본문을 읽어 아래 키워드가 나오는 문서와 나오지 않는 문서로
나눈다. 정보시스템 감리 업무에 참고할 만한 사례를 1000건이 넘는 자료에서
추려내는 것이 목적이다.

    정보화사업 / 전산시스템 / 정보시스템 / 시스템운영 / 시스템유지관리

한글 문서는 같은 말을 '시스템운영'과 '시스템 운영'처럼 띄어쓰기만 다르게 쓰는 일이
매우 흔하다. 그래서 본문과 키워드 양쪽에서 공백을 모두 지운 뒤 대조한다. 이렇게
하지 않으면 실제로 관련 있는 문서를 대량으로 놓친다.

사용 예:
    python classify_bai.py 감사결과 -o 분류결과.csv
    python classify_bai.py 감사결과/2026            # 한 해만
    python classify_bai.py 감사결과 --workers 8
"""

import argparse
import csv
import io
import json
import re
import sys
import zipfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

import olefile
import pymupdf
import struct
import zlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEYWORDS = ["정보화사업", "전산시스템", "정보시스템", "시스템운영", "시스템유지관리"]

# 분류를 바꾸지는 않지만 함께 세어 두면 경계선에 있는 문서를 사람이 판단할 때 도움이
# 된다. 예컨대 본 키워드는 없어도 '소프트웨어'와 '데이터베이스'가 잔뜩 나오는 문서는
# 들여다볼 값어치가 있다.
EXTRA_TERMS = ["정보화", "전산", "소프트웨어", "데이터베이스", "홈페이지",
               "정보보안", "개인정보", "디지털"]

# 글자가 이만큼도 안 나오면 본문이 없는 스캔 이미지로 본다. 이런 문서를 '무관'으로
# 묶어 버리면 실제로는 관련 있는 자료를 조용히 잃게 되므로 따로 표시한다.
MIN_CHARS_PER_PAGE = 30


def squash(s):
    """공백을 모두 제거해 띄어쓰기 차이를 무시한 대조가 가능하게 만든다."""
    return re.sub(r"\s+", "", s)


def read_pdf_text(data):
    """PDF 바이트에서 쪽별 텍스트를 뽑는다."""
    with pymupdf.open(stream=data, filetype="pdf") as doc:
        return [page.get_text() for page in doc]


class MsRand:
    """배포용 HWP가 키 난독화에 쓰는 MSVC rand()."""

    def __init__(self, seed):
        self.h = seed & 0xFFFFFFFF

    def __call__(self):
        self.h = (self.h * 214013 + 2531011) & 0xFFFFFFFF
        return (self.h >> 16) & 0x7FFF


def viewtext_key(payload):
    """배포용 문서의 256바이트 블록에서 AES 키를 꺼낸다.

    블록은 시드로 돌린 rand() 스트림과 XOR되어 있어 먼저 풀어야 하고, 키 위치는
    시드 하위 4비트가 정한다.
    """
    seed = struct.unpack("<I", payload[:4])[0]
    rnd = MsRand(seed)
    buf = bytearray(payload)
    n = temp = 0
    for i in range(256):
        if n == 0:
            temp = rnd() & 0xFF
            n = (rnd() & 0x0F) + 1
        if i >= 4:                       # 앞 4바이트는 시드라 그대로 둔다
            buf[i] ^= temp
        n -= 1
    off = 4 + (seed & 0x0F)
    return bytes(buf[off:off + 16])


def hwp_paragraphs(raw):
    """HWP 레코드 스트림에서 문단 텍스트(HWPTAG_PARA_TEXT)만 모은다.

    제어문자는 1워드짜리와 8워드짜리가 있어 길이를 맞춰 건너뛰지 않으면 이후 글자가
    통째로 어긋난다.
    """
    one = {0, 10, 13} | set(range(24, 32))
    out, i = [], 0
    while i + 4 <= len(raw):
        head = struct.unpack("<I", raw[i:i + 4])[0]
        i += 4
        tag, size = head & 0x3FF, (head >> 20) & 0xFFF
        if size == 0xFFF:
            if i + 4 > len(raw):
                break
            size = struct.unpack("<I", raw[i:i + 4])[0]
            i += 4
        body = raw[i:i + size]
        i += size
        if tag != 0x43:                  # HWPTAG_PARA_TEXT
            continue
        j, buf = 0, []
        while j + 1 < len(body):
            c = struct.unpack("<H", body[j:j + 2])[0]
            if c >= 32:
                buf.append(chr(c))
                j += 2
            elif c in one:
                buf.append("\n" if c in (10, 13) else " ")
                j += 2
            else:
                j += 16
        out.append("".join(buf))
    return out


def read_hwp_text(data):
    """HWP 5.x 본문 텍스트. 배포용 문서는 ViewText를 복호화해서 읽는다."""
    ole = olefile.OleFileIO(io.BytesIO(data))
    try:
        tops = {e[0] for e in ole.listdir()}
        # 배포용 문서는 BodyText에 '상위 버전 문서' 안내문만 두고 실제 본문은
        # ViewText에 암호화해 넣는다. BodyText만 읽으면 빈 문서로 보인다.
        src = "ViewText" if "ViewText" in tops else "BodyText"
        paras = []
        for entry in sorted((e for e in ole.listdir() if e[0] == src),
                            key=lambda e: e[1]):
            raw = ole.openstream(entry).read()
            if src == "ViewText":
                key = viewtext_key(raw[4:260])
                enc = raw[260:]
                enc = enc[:len(enc) - len(enc) % 16]
                dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
                raw = dec.update(enc) + dec.finalize()
            try:
                raw = zlib.decompress(raw, -15)
            except zlib.error:
                pass                      # 비압축 저장인 경우
            paras.extend(hwp_paragraphs(raw))
        return paras
    finally:
        ole.close()


def read_any(data, name):
    """확장자가 아니라 실제 내용으로 형식을 판별해 쪽(또는 문단) 목록을 돌려준다."""
    if data[:4] == b"%PDF":
        return read_pdf_text(data)
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return read_hwp_text(data)
    raise ValueError(f"알 수 없는 형식: {name} ({data[:8].hex()})")


def extract_pages(path):
    """파일 하나에서 텍스트 조각 목록을 얻는다. ZIP이면 안쪽 문서를 모두 합친다."""
    if path.suffix.lower() in (".zip", ".hwpx"):
        pages, inner = [], []
        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                if not name.lower().endswith((".pdf", ".hwp")):
                    continue
                inner.append(name)
                try:
                    pages.extend(read_any(z.read(name), name))
                except Exception as e:                       # noqa: BLE001
                    pages.append("")
                    print(f"  ! ZIP 내부 읽기 실패: {path.name}/{name} ({e})",
                          file=sys.stderr)
        return pages, inner
    return read_any(path.read_bytes(), path.name), []


def analyze(path_str):
    path = Path(path_str)
    rec = {
        "연도": path.parent.name,
        "파일명": path.name,
        "형식": path.suffix.lstrip(".").upper(),
        "ZIP내부파일": "",
        "쪽수": 0,
        "본문글자수": 0,
        "분류": "",
        "관련도": "",
        "매칭키워드": "",
        "총매칭수": 0,
        "첫매칭쪽": "",
        "발췌": "",
        "오류": "",
    }
    for k in KEYWORDS:
        rec[k] = 0
    for k in EXTRA_TERMS:
        rec["참고:" + k] = 0

    try:
        pages, inner = extract_pages(path)
    except Exception as e:                                   # noqa: BLE001
        rec["분류"] = "읽기실패"
        rec["오류"] = str(e)[:200]
        return rec

    rec["ZIP내부파일"] = " | ".join(inner)
    rec["쪽수"] = len(pages)
    full = "\n".join(pages)
    rec["본문글자수"] = len(full)

    squashed_pages = [squash(p) for p in pages]
    whole = "".join(squashed_pages)

    hits, first_page, snippet = [], None, ""
    for kw in KEYWORDS:
        key = squash(kw)
        n = whole.count(key)
        rec[kw] = n
        if n:
            hits.append(f"{kw}({n})")
            for i, sp in enumerate(squashed_pages, 1):
                if key in sp:
                    if first_page is None or i < first_page:
                        first_page = i
                        pos = sp.index(key)
                        snippet = sp[max(0, pos - 35):pos + len(key) + 35]
                    break

    for term in EXTRA_TERMS:
        rec["참고:" + term] = whole.count(squash(term))

    total = sum(rec[k] for k in KEYWORDS)
    rec["매칭키워드"] = ", ".join(hits)
    rec["총매칭수"] = total
    rec["첫매칭쪽"] = first_page or ""
    rec["발췌"] = snippet

    if total:
        rec["분류"] = "관련"
    elif not rec["본문글자수"]:
        # 글자가 한 자도 안 나온 문서를 '무관'으로 넣으면 조용히 잃는다.
        rec["분류"] = "판정불가(본문없음)"
    elif (rec["형식"] == "PDF" and rec["쪽수"]
          and rec["본문글자수"] / rec["쪽수"] < MIN_CHARS_PER_PAGE):
        # 텍스트 층이 없는 스캔본. 키워드가 없는 게 아니라 읽을 수 없었던 것이다.
        # HWP는 '쪽수'가 문단 수라 이 기준이 맞지 않으므로 적용하지 않는다.
        rec["분류"] = "판정불가(스캔본)"
    else:
        rec["분류"] = "무관"

    # 파일명이 '등록일자_감사사항' 형식이라 제목은 manifest 없이도 얻을 수 있다.
    rec["관련도"] = grade(rec, total, re.sub(r"^\d{8}_", "", path.stem))
    return rec


def grade(rec, total, title):
    """'포함되었다'와 '감사 대상이었다'는 다르다.

    수백 쪽짜리 정기감사 보고서에는 각주 한 줄에 '토지이용규제정보시스템' 같은 말이
    스치기만 해도 키워드가 잡힌다. 실제로 정보시스템을 감사한 문서와 섞이면 골라내는
    수고가 그대로 남으므로, 제목 일치와 등장 빈도로 강도를 나눠 둔다.
    """
    if not total:
        return ""
    t = squash(title)
    if t and any(squash(k) in t for k in KEYWORDS):
        return "높음(제목일치)"
    per100 = total / max(rec["쪽수"], 1) * 100
    if total >= 20 or per100 >= 20:
        return "높음"
    if total >= 5:
        return "중간"
    return "낮음(단순언급)"


def load_manifest(root):
    """다운로드 때 남긴 manifest에서 감사종류·감사분야를 파일명으로 찾아 쓴다."""
    meta = {}
    for mp in root.rglob("manifest.json"):
        try:
            for r in json.loads(mp.read_text(encoding="utf-8")):
                if r.get("filename"):
                    meta[Path(r["filename"]).stem] = r
        except Exception:                                    # noqa: BLE001
            pass
    return meta


def main():
    ap = argparse.ArgumentParser(
        description="감사원 전문 PDF에서 정보화/정보시스템 관련 문서를 가려낸다")
    ap.add_argument("root", help="감사결과 폴더 (연도별 하위폴더 포함)")
    ap.add_argument("-o", "--out", default="분류결과.csv", help="결과 CSV 경로")
    ap.add_argument("--workers", type=int, default=4, help="병렬 처리 수 (기본 4)")
    args = ap.parse_args()

    root = Path(args.root)
    exts = (".pdf", ".hwp", ".hwpx", ".zip")
    dirs = sorted(d for d in root.iterdir() if d.is_dir()) or [root]
    files = sorted(
        p for d in dirs for p in d.rglob("*")
        if p.suffix.lower() in exts and p.is_file()
    )
    if not files:
        sys.exit(f"{root} 에서 PDF/ZIP을 찾지 못했다.")
    print(f"대상 {len(files)}건 분석 시작 (병렬 {args.workers})", flush=True)

    meta = load_manifest(root)
    rows, done = [], 0
    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        futs = {ex.submit(analyze, str(p)): p for p in files}
        for fut in as_completed(futs):
            rec = fut.result()
            m = meta.get(Path(rec["파일명"]).stem, {})
            rec["감사사항"] = m.get("titNm", "")
            rec["감사종류"] = m.get("audKndNm", "") or ""
            rec["감사분야"] = m.get("audSphDtlNm", "") or ""
            rec["담당부서"] = m.get("hndlDptNm", "") or ""
            rows.append(rec)
            done += 1
            if done % 50 == 0 or done == len(files):
                print(f"  {done}/{len(files)}", flush=True)

    rows.sort(key=lambda r: (r["연도"], r["파일명"]), reverse=True)

    cols = (["연도", "파일명", "감사사항", "감사종류", "감사분야", "담당부서",
             "분류", "관련도", "매칭키워드", "총매칭수", "첫매칭쪽", "쪽수", "본문글자수"]
            + KEYWORDS + ["참고:" + t for t in EXTRA_TERMS]
            + ["발췌", "형식", "ZIP내부파일", "오류"])

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    # 엑셀에서 한글이 깨지지 않도록 BOM을 붙인다.
    with out.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)

    rel = [r for r in rows if r["분류"] == "관련"]
    unrel = [r for r in rows if r["분류"] == "무관"]
    scan = [r for r in rows if r["분류"].startswith("판정불가")]
    err = [r for r in rows if r["분류"] == "읽기실패"]

    print(f"\n{'=' * 46}")
    print(f"관련        {len(rel):5d}건")
    print(f"무관        {len(unrel):5d}건")
    if scan:
        print(f"판정불가    {len(scan):5d}건  (스캔본, 본문 텍스트 없음)")
    if err:
        print(f"읽기실패    {len(err):5d}건")
    print(f"{'=' * 46}")

    print("\n'관련' 안에서의 관련도:")
    for g in ["높음(제목일치)", "높음", "중간", "낮음(단순언급)"]:
        n = sum(1 for r in rel if r["관련도"] == g)
        print(f"  {g:<14} {n:4d}건")

    print("\n키워드별 등장 문서 수:")
    for kw in KEYWORDS:
        print(f"  {kw:<12} {sum(1 for r in rows if r[kw]):4d}건")

    print("\n연도별 관련 문서:")
    years = sorted({r["연도"] for r in rows}, reverse=True)
    for y in years:
        yr = [r for r in rows if r["연도"] == y]
        yrel = [r for r in yr if r["분류"] == "관련"]
        pct = len(yrel) / len(yr) * 100 if yr else 0
        print(f"  {y}  {len(yrel):3d}/{len(yr):3d}건 ({pct:4.1f}%)")

    print(f"\n결과: {out}")


if __name__ == "__main__":
    main()
