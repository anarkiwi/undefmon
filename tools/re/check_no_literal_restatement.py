"""Verify gate (observe mode): detect literal code-restatement in `notes`.

A sentence in a function's `notes` is "literal restatement" when its
content is entirely:

- one or more action verbs (copies, calls, JSRs, reads, writes, ...)
- one or more labels that already appear in this function's instruction
  stream (operand targets, callees)
- direction arrows (→, ←) and glue words (then, and, the, ...)

Those sentences add nothing the disassembly doesn't already show — the
labels render the operand targets, the mnemonic names the action. The
catalog should either delete them or convert any per-instruction
semantic fragment into a future `inline_comments` field.

Observe mode (default): prints flagged sentences with their function +
counts; exits 0. With `--fail`: exits 1 if any hits.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from tools.re.dasm6502 import fmt_operand
from tools.re.emit_defmon_source import (
    EQUATE_LABELS,
    HW_LABELS,
    LOAD_ADDR,
    END_ADDR_EXCL,
    SEED_LANDMARKS,
    classify,
    expand_code_starts,
    extract_annotation_labels,
    load_annotations,
    load_code_starts,
    load_ghidra_labels,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
BIN = REPO_ROOT / "artefacts" / "defmon-static.bin"
ANNOTATIONS = REPO_ROOT / "tools" / "re" / "annotations.toml"
ENTRYPOINTS = REPO_ROOT / "trace" / "entrypoints.json"
GHIDRA = REPO_ROOT / "artefacts" / "ghidra"

# Action verbs that re-narrate what an instruction does. Listed in
# multiple inflections; lowercased before lookup.
LITERAL_VERBS = {
    "copies", "copy", "copying",
    "reads", "read", "reading",
    "writes", "write", "writing",
    "loads", "load", "loading",
    "stores", "store", "storing",
    "calls", "call", "calling",
    "jsr", "jsrs",
    "jumps", "jump", "jumping",
    "jmp", "jmps",
    "branches", "branch", "branching",
    "bcc", "bcs", "beq", "bne", "bmi", "bpl", "bvc", "bvs",
    "increments", "increment", "incrementing", "inc", "incs",
    "decrements", "decrement", "decrementing", "dec", "decs",
    "saves", "save", "saving",
    "restores", "restore", "restoring",
    "pushes", "push", "pushing",
    "pops", "pop", "popping",
    "transfers", "transfer", "transferring",
    "shifts", "shift", "shifting",
    "compares", "compare", "comparing",
    "ands", "ors", "eors", "anding", "oring", "eoring",
    "falls",
    "exits", "exit", "returns", "return", "returning",
    "lda", "ldx", "ldy", "sta", "stx", "sty",
    "adc", "sbc", "cmp", "cpx", "cpy",
    "tay", "tax", "tya", "txa", "tsx", "txs",
    "pha", "pla", "php", "plp",
    "clc", "sec", "cli", "sei",
    "asl", "lsr", "rol", "ror", "bit",
    "rts", "rti",
}

# Generic glue / structural words that appear in any prose. A
# restatement sentence is allowed to use these freely.
GLUE_WORDS = {
    "the", "a", "an", "of", "to", "from", "into", "via", "with", "in",
    "at", "on", "off", "and", "or", "then", "next", "first", "last",
    "for", "by", "this", "that", "is", "are", "was", "were", "be",
    "been", "being", "it", "its", "them", "their", "these", "those",
    "as", "so", "out", "up", "down", "through",
    "x", "y", "z", "s",
    "lo", "hi", "lo/hi",
    "p1", "p2", "ptr",
    "carry", "flag", "byte", "bytes", "word", "value", "register",
    "operand", "operands", "instruction", "instructions",
    "code", "address", "addresses", "low", "high",
    "block", "loop", "tail", "head", "start", "end", "row", "col",
    "step", "stride", "pair", "page", "frame",
    "no", "yes", "true", "false",
    "n", "m", "k",
    "all", "each", "every", "any", "some",
    "result", "results",
    "current", "previous", "next-",
}

# Tokens that indicate the sentence is doing more than restatement —
# explaining WHY, naming a sentinel meaning, citing a constraint.
# Presence of any of these makes the sentence "content-bearing".
CONTENT_INDICATORS = re.compile(
    r"\b(?:because|since|so\s+that|in\s+order\s+to|in\s+order\s+for|"
    r"to\s+(?:prevent|allow|ensure|avoid|guarantee|skip|reset|recover|"
    r"trigger|enter|exit|preserve|mark|signal|indicate|mean|represent|"
    r"keep|stop|start|defer|short[- ]circuit|emulate|implement|model|"
    r"protect|isolate|distinguish|differentiate)|"
    r"shared|preserves|preserved|fallback|fall[- ]?through|"
    r"represents?|indicates?|means|signals?|signaling|signalling|"
    r"acts?\s+as|used\s+by|used\s+to|written\s+by|read\s+by|"
    r"prefix|suffix|marker|sentinel|magic|"
    r"layout|format|encoding|scheme|invariant|protocol|"
    r"never|always|only|"
    r"reset|cleared|primed|"
    r"because\s+of|due\s+to|driven\s+by|controlled\s+by|gated\s+by|"
    r"semantics?|meaning|purpose|rationale|"
    r"unlike|whereas|but|however|except|"
    r"identical\s+to|equivalent\s+to|analogous\s+to|"
    r"caller|callers|callee|callees|"
    r"convention|contract|guarantee|"
    r"the\s+only|the\s+one|the\s+sole|"
    r"safe\s+to|unsafe\s+to|"
    r"must|should|cannot|won['']t|do(?:es)?\s+not|doesn['']t|"
    r"\$\d|\#\$"
    r")\b",
    re.IGNORECASE,
)

# Punctuation we treat as token-internal direction markers (and ignore).
_ARROW_RE = re.compile(r"[→←]")


def _strip_sequence_blocks(text: str) -> str:
    """Drop `Sequence:` bullet blocks.

    The Sequence: bullet block is consumed by the emitter's bullet
    inliner (`b7f407c`) — when alignment succeeds, the block is moved
    inline above its matching instructions. When alignment fails it
    stays in the header, but in either case the gate's job is to flag
    *prose* restatement, not structured bullet lists.

    Sequence: can appear either as its own paragraph header or as
    an inline marker mid-paragraph ("Fires when X. Sequence:\\n  - …").
    In both cases we drop the bulleted block that follows.
    """
    lines = text.split("\n")
    out: list[str] = []
    i = 0
    n = len(lines)
    while i < n:
        # Strip trailing "Sequence:" off the current line if present;
        # then skip the following bullet/indented block.
        line = lines[i]
        m = re.search(r"\bSequence:\s*$", line)
        if m:
            # Keep the prose before "Sequence:", drop the marker.
            kept = line[:m.start()].rstrip()
            if kept:
                out.append(kept)
            i += 1
            # Skip the bullet block: any line that begins with "  - "
            # or is just whitespace.
            while i < n:
                s = lines[i]
                if re.match(r"^\s*-\s", s) or re.match(r"^\s+\S", s):
                    i += 1
                    continue
                if not s.strip():
                    # blank line — terminates the block.
                    i += 1
                    break
                break
            continue
        out.append(line)
        i += 1
    return "\n".join(out)


def _split_sentences(text: str) -> list[str]:
    """Split text into sentences. Same heuristic as _strip_forward_refs:
    only split when sentence-end is followed by a capital letter, so
    abbreviations like e.g./i.e. don't cleave a sentence mid-word."""
    return [s.strip() for s
            in re.split(r"(?<=[.!?])\s+(?=[A-Z])", text.strip())
            if s.strip()]


def _walk_linear_block(instr_at, mem, start_pc, max_instrs=128):
    pcs: list[int] = []
    pc = start_pc
    while pc in instr_at and len(pcs) < max_instrs:
        pcs.append(pc)
        _, _, n = instr_at[pc]
        op = mem[pc]
        if op in (0x60, 0x40, 0x4C, 0x6C, 0x00):  # RTS RTI JMP BRK
            break
        pc += n
    return pcs


def _function_operand_labels(instr_at, mem, labels, addr) -> set[str]:
    """All operand-target labels referenced in the function's linear
    block. Includes JSR/JMP/branch targets and absolute memory operands."""
    out: set[str] = set()
    for pc in _walk_linear_block(instr_at, mem, addr):
        _, mode, n = instr_at[pc]
        p1 = mem[pc + 1] if n >= 2 else 0
        p2 = mem[pc + 2] if n >= 3 else 0
        _, tgt = fmt_operand(mode, p1, p2, pc, labels)
        if tgt is not None and tgt in labels:
            out.add(labels[tgt])
    return out


def classify_sentence(sentence: str, in_func: set[str]) -> str | None:
    """Classify a sentence:
        "pure"  — every token is a literal-verb / in-function-label /
                  arrow / glue. No content indicators. Strong delete
                  candidate.
        "heavy" — sentence has ≥3 literal verbs AND ≥2 in-function
                  labels — dominated by restatement even though some
                  content tokens may also be present. Worth a triage.
        None    — content-bearing prose.
    """
    text = _ARROW_RE.sub(" ", sentence)
    words = re.findall(r"[A-Za-z_][A-Za-z0-9_/+\-]*", text)
    if not words:
        return None
    verb_count = 0
    label_count = 0
    unknown_count = 0
    for w in words:
        wl = w.lower()
        if wl in LITERAL_VERBS:
            verb_count += 1
            continue
        if w in in_func:
            label_count += 1
            continue
        if wl in GLUE_WORDS:
            continue
        unknown_count += 1
    if verb_count == 0 or label_count == 0:
        return None
    if not CONTENT_INDICATORS.search(sentence) and unknown_count <= 1:
        return "pure"
    # "heavy" is the mixed case: many mechanics + some content. The
    # thresholds are tuned to catch sentences that read as a step list
    # ("Copies X → Y, then call Z, then call W, then call V"). A
    # sentence with one verb and one label but some content (e.g. "X
    # then writes the result to Y") is not heavy — it's normal prose.
    if verb_count >= 3 and label_count >= 2:
        return "heavy"
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fail", action="store_true",
                    help="Exit 1 if any sentences flagged.")
    ap.add_argument("--show", type=int, default=20,
                    help="Show N flagged functions (default 20).")
    ap.add_argument("--all", action="store_true",
                    help="Show all flagged functions (overrides --show).")
    args = ap.parse_args()

    mem = BIN.read_bytes()
    if len(mem) < END_ADDR_EXCL:
        print(f"check_no_literal_restatement: image too short ({len(mem)} bytes)",
              file=sys.stderr)
        return 2

    code_starts = load_code_starts(ENTRYPOINTS)
    code_starts.update(SEED_LANDMARKS.keys())
    expanded = expand_code_starts(mem, code_starts, LOAD_ADDR, END_ADDR_EXCL)
    instr_at, _ = classify(mem, expanded, LOAD_ADDR, END_ADDR_EXCL)

    annotations = load_annotations(ANNOTATIONS)
    labels: dict[int, str] = {}
    labels.update(SEED_LANDMARKS)
    labels.update(EQUATE_LABELS)
    for addr, name in HW_LABELS.items():
        labels.setdefault(addr, name)
    sym_path = GHIDRA / "symbols.json"
    if sym_path.is_file():
        for addr, name in load_ghidra_labels(sym_path).items():
            labels.setdefault(addr, name)
    for addr, name in extract_annotation_labels(annotations).items():
        labels[addr] = name

    flagged: list[tuple[str, int, str, str]] = []  # (kind, addr, name, sent)
    func_count = 0
    sent_total = 0
    for addr, ann in annotations.items():
        if addr not in instr_at:
            continue
        notes = ann.get("notes", "")
        if not notes:
            continue
        func_count += 1
        in_func = _function_operand_labels(instr_at, mem, labels, addr)
        for s in _split_sentences(_strip_sequence_blocks(notes)):
            sent_total += 1
            kind = classify_sentence(s, in_func)
            if kind:
                flagged.append((kind, addr, ann.get("name", "?"), s))

    print(f"check_no_literal_restatement: scanned {func_count} function "
          f"annotations / {sent_total} sentences in `notes`.")
    if not flagged:
        print("OK — no literal-restatement sentences detected.")
        return 0

    pure_count = sum(1 for k, *_ in flagged if k == "pure")
    heavy_count = sum(1 for k, *_ in flagged if k == "heavy")
    pure_funcs = len({a for k, a, *_ in flagged if k == "pure"})
    heavy_funcs = len({a for k, a, *_ in flagged if k == "heavy"})
    print(f"flagged: {pure_count} pure-restatement ({pure_funcs} functions), "
          f"{heavy_count} heavy-restatement ({heavy_funcs} functions).")
    show = len(flagged) if args.all else args.show
    for kind, label in (("pure", "pure-restatement"),
                        ("heavy", "heavy-restatement (mixed)")):
        bucket = [(a, n, s) for k, a, n, s in flagged if k == kind]
        if not bucket:
            continue
        print(f"\n--- {label} ---")
        by_addr: dict[tuple[int, str], list[str]] = {}
        for a, n, s in bucket:
            by_addr.setdefault((a, n), []).append(s)
        for (addr, name), sents in sorted(by_addr.items())[:show]:
            print(f"  ${addr:04X}  {name}:")
            for s in sents[:2]:
                print(f"    - {s[:180]}")
            if len(sents) > 2:
                print(f"    ... +{len(sents) - 2} more")
        if len(by_addr) > show:
            print(f"  ... +{len(by_addr) - show} more functions "
                  f"(rerun with --all to see them).")

    if args.fail:
        return 1
    print("\n(observe mode — exit 0; run with --fail to gate.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
