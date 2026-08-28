#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""감사보고서에서 지적사항 제목을 뽑아낸다.

보고서마다 목차 서식이 제각각이라 한 가지 방법으로는 다 못 잡는다. 두 갈래로 훑고
합친다.

  1) 목차 방식 - `제목······32` 처럼 점선과 쪽번호가 붙은 줄. PDF에 흔하다.
     쪽번호가 다음 줄로 넘어간 형태도 함께 본다.
  2) 처분요구 방식 - `○○시스템 구축 부적정(통보)` 처럼 처분 종류가 괄호로 붙은 것.
     HWP처럼 점선이 서식이라 글자로 안 나오는 문서에서 특히 잘 걸린다.

2)는 본문 문장 한복판도 걸리므로(`…하도록 하고(통보)`) 어미로 끝나는 것은 버린다.
지적사항 제목은 '부적정·미흡·부실' 같은 명사형으로 끝나는 것이 감사원 관행이다.
"""

import argparse
import csv
import re
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from classify_bai import KEYWORDS, extract_pages, squash        # noqa: E402

DISP = (r"변상판정|징계|문책|시정|주의|개선|권고|통보|고발|수사요청"
        r"|해임|정직|감봉|견책")

# 처분요구가 괄호로 붙은 지적사항
RE_DISP = re.compile(
    r"(?P<t>[가-힣A-Za-z0-9()·\[\]/ ,‘’“”%\-]{8,90}?)\s*"
    r"\(\s*(?P<d>(?:" + DISP + r")(?:\s*요구)?\s*\d*)\s*\)")

# 목차 줄: 제목 + 점선 + 쪽번호
RE_TOC = re.compile(r"^(?P<t>.{6,90}?)\s*[·.]{3,}\s*(?P<p>\d{1,4})\s*$")

# 앞머리 번호 (`1-가-1)`, `(3)`, `가.` 등)
RE_NUM = re.compile(r"^\s*(?:\(\d+\)|\d+[-–][가-힣][-–]?\d*\s*[).]?|\d+\s*[).]|[가-힣]\s*[).])\s*")

# 지적사항 제목이 끝나는 말. 감사원은 명사형으로 맺는다.
TAIL = ("부적정", "미흡", "부실", "부재", "소홀", "미비", "누락", "위반", "부당",
        "불합리", "한계", "실패", "지연", "과다", "과소", "방치", "저조", "중복",
        "불일치", "미반영", "부정확", "불투명", "혼선", "차질", "낭비", "미조치",
        "불명확", "필요", "개선", "곤란", "미이행", "미흡함", "불충분", "부적절",
        "허술", "누수", "오류", "장애", "취약")

# 문장 한복판을 걸러내는 어미
VERB_END = ("하고", "하며", "한편", "하도록", "하여", "되고", "되며", "하라",
            "하기", "있고", "있으며", "면서", "으며", "이고", "토록", "하는",
            "받고", "지도", "따라", "대해", "위해", "함으로", "인해")

SKIP = ("감사실시", "감사대상", "감사결과 요약", "별표", "목차", "감사배경",
        "감사중점", "참고자료", "용어", "약어", "붙임", "총괄", "처분요구와",
        "감사결과 총괄", "이 보고서", "감 사 원", "감사원")


def clean(t):
    t = re.sub(r"\s+", " ", t).strip(" ·.-,")
    t = RE_NUM.sub("", t).strip(" ·.-,")
    return t


def keep(t):
    if len(t) < 8 or len(t) > 90:
        return False
    if any(s in t for s in SKIP):
        return False
    if t.endswith(VERB_END):
        return False
    # 명사형 마무리 확인. 뒤쪽 8자 안에 지적 어휘가 있으면 지적사항으로 본다.
    return any(w in t[-8:] for w in TAIL)


def findings_of(path_str):
    path = Path(path_str)
    try:
        pages, _ = extract_pages(path)
    except Exception as e:                                       # noqa: BLE001
        return path.name, [], str(e)[:120]

    txt = "\n".join(pages)
    lines = txt.splitlines()
    found = {}

    # 1) 목차 - 점선 + 쪽번호
    for line in lines:
        m = RE_TOC.match(line.strip())
        if not m:
            continue
        t = clean(m.group("t"))
        if keep(t):
            found.setdefault(t, "목차")

    # 1-b) 제목과 쪽번호가 두 줄로 갈린 목차 (앞부분에만 나타난다)
    head = lines[:400]
    for a, b in zip(head, head[1:]):
        if not re.fullmatch(r"\d{1,4}", b.strip()):
            continue
        t = clean(a)
        if keep(t):
            found.setdefault(t, "목차")

    # 2) 처분요구가 붙은 지적사항
    for m in RE_DISP.finditer(txt):
        t = clean(m.group("t"))
        if keep(t):
            found.setdefault(t, re.sub(r"\s+", "", m.group("d")))

    out = []
    for t, src in found.items():
        sq = squash(t)
        out.append({
            "지적사항": t,
            "처분": src if src != "목차" else "",
            "출처": src,
            "제목내키워드": ",".join(k for k in KEYWORDS if squash(k) in sq),
        })
    return path.name, out, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("-o", "--out", default="지적사항.csv")
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()

    root = Path(args.root)
    files = sorted(p for p in root.rglob("*") if p.is_file()
                   and p.suffix.lower() in (".pdf", ".hwp", ".zip", ".hwpx"))
    print(f"대상 {len(files)}건", flush=True)

    rows, errs, empty = [], [], []
    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        futs = [ex.submit(findings_of, str(p)) for p in files]
        for i, fut in enumerate(as_completed(futs), 1):
            name, items, err = fut.result()
            if err:
                errs.append((name, err))
            elif not items:
                empty.append(name)
            for it in items:
                rows.append({"연도": name[:4], "보고서": name, **it})
            if i % 20 == 0 or i == len(files):
                print(f"  {i}/{len(files)}", flush=True)

    out = Path(args.out)
    with out.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["연도", "보고서", "지적사항", "처분",
                                          "출처", "제목내키워드"])
        w.writeheader()
        w.writerows(sorted(rows, key=lambda r: (r["연도"], r["보고서"]), reverse=True))

    print(f"\n지적사항 {len(rows)}건 / 보고서 {len(set(r['보고서'] for r in rows))}건")
    print(f"한 건도 못 뽑은 보고서 {len(empty)}건, 읽기 실패 {len(errs)}건")
    print("결과:", out)


if __name__ == "__main__":
    main()
