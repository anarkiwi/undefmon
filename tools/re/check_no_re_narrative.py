"""Verify gate: no RE-process narrative or pseudo-hex in semantic fields.

Bans phrases that describe the *reverse-engineering process* (tool names,
xref forensics, probe narrative, doc cross-refs) and pseudo-hex address
ranges (`$74xx`, `$D6xx`). These belong in `evidence` / `internal_notes`,
where the historical RE context is preserved.

Checked fields: summary, notes, callers, inputs, outputs, clobbers, values.
Exempt: evidence, internal_notes (preserves probe CLI commands +
historical incident references).

Exits 1 with offending list; exits 0 if clean.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from tools.re.emit_defmon_source import load_annotations

REPO_ROOT = Path(__file__).resolve().parents[2]
ANNOTATIONS = REPO_ROOT / "tools" / "re" / "annotations.toml"

CHECK_FIELDS = {"role", "notes", "callers", "inputs",
                "outputs", "registers_clobbered", "variables_changed", "values"}

# Patterns banned in semantic prose. Each entry: (regex, label).
BANNED = [
    # RE tool references
    (re.compile(r"\bdasm6502\b"), "RE-tool ref (dasm6502)"),
    (re.compile(r"\blinear scanner\b"), "tool-internals ref"),
    (re.compile(r"\btrace_runner\b"), "tool-internals ref"),
    (re.compile(r"\bharness/probe", re.IGNORECASE), "probe narrative"),
    (re.compile(r"\bprobe_[a-z0-9_]+\.py"), "probe filename"),
    # Bare probe-script names (without .py) also leak into prose as
    # "probe_function_attribution never-hits …" etc. Keep them in
    # evidence/internal_notes where the citation context belongs.
    (re.compile(r"\bprobe_[a-z][a-z0-9_]+\b"), "probe ref"),
    (re.compile(r"\bnever observed executing\b", re.IGNORECASE),
     "probe narrative"),
    (re.compile(r"\bnever[_-]hits?\b", re.IGNORECASE), "probe narrative"),
    # Xref forensics
    (re.compile(r"\bxrefs?\b"), "RE xref jargon"),
    (re.compile(r"\bProbe captured\b"), "probe narrative"),
    (re.compile(r"\bnot real call sites?\b"), "xref forensics"),
    (re.compile(r"\bnot an executable jsr\b", re.IGNORECASE), "xref forensics"),
    (re.compile(r"\bscreen-text data byte"), "xref forensics"),
    (re.compile(r"\bspurious '?(?:jsr|call) "), "xref forensics"),
    (re.compile(r"\bas instruction starts?\b"), "tool-internals ref"),
    (re.compile(r"\bbyte-coverage\b"), "probe narrative"),
    (re.compile(r"\bstatic-vs-live\b"), "RE jargon"),
    # Self-reference
    (re.compile(r"\bis mentioned by name\b"), "self-reference"),
    # Doc cross-refs that don't belong in semantic prose. AGENTS.md
    # and the wiki/SPEC are RE-process scaffolding — semantic prose
    # should describe the code, not the history of how we labelled it.
    (re.compile(r"\bAGENTS(\+\+|\.md)?\b"), "AGENTS doc cross-ref"),
    (re.compile(r"\bper AGENTS\b"), "doc cross-ref"),
    (re.compile(r"\bSPEC\b"), "spec cross-ref"),
    (re.compile(r"§\d+"), "section cross-ref"),
    (re.compile(r"\bPhase \d+[a-z]?\b"), "phase cross-ref"),
    (re.compile(r"\bGhidra\b"), "Ghidra cross-ref"),
    (re.compile(r"\bthe wiki\b", re.IGNORECASE), "wiki cross-ref"),
    # Prior-hypothesis correction narrative — these belong in
    # internal_notes / [refuted], not in user-facing prose. The fix
    # is to state what the code *does*, not to apologise for what an
    # earlier annotation thought it did.
    (re.compile(r"\bprior annotation\b", re.IGNORECASE),
     "prior-annotation narrative"),
    (re.compile(r"\bprevious annotation\b", re.IGNORECASE),
     "prior-annotation narrative"),
    (re.compile(r"\b(as|like) [^.]{0,40}\b(previously|originally|earlier)\s+"
                r"(claim|said|labe|wrote|name|annotated|thought)",
                re.IGNORECASE), "prior-claim narrative"),
    (re.compile(r"\boriginal AGENTS\b", re.IGNORECASE),
     "prior-doc narrative"),
    # "the earlier X name was Y" / "the previous label was Z" —
    # narrative explaining a renaming. The catalog is the current
    # name; old names live in [refuted] or git history.
    (re.compile(r"\bthe earlier ['\"]\w[\w_]*['\"] name\b", re.IGNORECASE),
     "prior-annotation narrative"),
    (re.compile(r"\bname was too (narrow|broad|vague|imprecise)\b",
                re.IGNORECASE), "prior-annotation narrative"),
    # Annotation-meta about maintenance/porting (cross-project leak).
    (re.compile(r"\bRemoving or rewriting these\b", re.IGNORECASE),
     "annotation-meta porting note"),
    (re.compile(r"\bwill assemble to wrong bytes\b", re.IGNORECASE),
     "annotation-meta porting note"),
    (re.compile(r"\bdocumented-only opcode list\b", re.IGNORECASE),
     "annotation-meta porting note"),
    (re.compile(r"\bwas a misread\b", re.IGNORECASE),
     "prior-claim narrative"),
    (re.compile(r"\bwas wrong\b", re.IGNORECASE),
     "prior-claim narrative"),
    (re.compile(r"\bwas incomplete\b", re.IGNORECASE),
     "prior-claim narrative"),
    (re.compile(r"\bRemaining (work )?item\b", re.IGNORECASE),
     "RE-roadmap narrative"),
    # Date-stamped notes. Every date in this codebase is an RE-pass
    # date and belongs in evidence/internal_notes alongside the
    # probe artefact, not in the user-facing prose.
    (re.compile(r"\b20\d{2}-\d{2}-\d{2}\b"), "date stamp"),
    (re.compile(r"\bverified \d", re.IGNORECASE),
     "verification narrative"),
    # Speculation. "likely" / "may be" / "might be" / "perhaps"
    # signal RE-narrative guesses about intent or purpose. The catalog
    # is reverse-engineered code; if we know what it does, say so. If
    # we don't, leave it un-annotated rather than guessing in prose.
    (re.compile(r"\blikely\b", re.IGNORECASE), "speculation"),
    (re.compile(r"\bmay be\b", re.IGNORECASE), "speculation"),
    (re.compile(r"\bmight be\b", re.IGNORECASE), "speculation"),
    (re.compile(r"\bperhaps\b", re.IGNORECASE), "speculation"),
    (re.compile(r"\bpossibly\b", re.IGNORECASE), "speculation"),
    (re.compile(r"\bprobably chosen\b", re.IGNORECASE), "speculation"),
    (re.compile(r"\bprobably reached\b", re.IGNORECASE), "speculation"),
    (re.compile(r"\bconsider removal in a future\b", re.IGNORECASE),
     "speculation"),
    (re.compile(r"\bbody shape suggests\b", re.IGNORECASE), "speculation"),
    (re.compile(r"\bsuggests?\b", re.IGNORECASE), "speculation"),
    (re.compile(r"\bnot yet identified\b", re.IGNORECASE),
     "RE-status speculation"),
    (re.compile(r"\bnot yet located\b", re.IGNORECASE),
     "RE-status speculation"),
    (re.compile(r"\bnot yet known\b", re.IGNORECASE),
     "RE-status speculation"),
    (re.compile(r"\byet to be (identified|located|mapped|named)\b",
                re.IGNORECASE), "RE-status speculation"),
    # Author-intent narrative. Speculating about why the author wrote
    # something belongs nowhere — describe what the code does, not
    # what we imagine they meant. Pattern only catches noun usage
    # ("the author", "author's", "defMON's author"), not verb usage
    # ("authors JP rows", "the tune authors a JP source").
    (re.compile(r"\b(the|defMON's|original)\s+author\b",
                re.IGNORECASE), "author-intent narrative"),
    (re.compile(r"\bauthor's\b", re.IGNORECASE), "author-intent narrative"),
    # Cross-project leakage. defMON annotations are about defMON; the
    # Python player port lives in a separate repo (preframr).
    (re.compile(r"\bplayer port\b", re.IGNORECASE), "cross-project leakage"),
    (re.compile(r"\bPython player\b", re.IGNORECASE),
     "cross-project leakage"),
    (re.compile(r"\bImplications? for\b.{0,30}\bport\b", re.IGNORECASE),
     "cross-project leakage"),
    # Runtime-coverage observation framing.
    (re.compile(r"\bobserved runtime\b", re.IGNORECASE),
     "coverage narrative"),
    # PC-coverage / probe stats. Counts like "Hit 58/264 PCs" or
    # "~110 distinct PCs to the coverage trace" belong in `evidence`
    # alongside the probe artefact citation, not in user-facing prose.
    (re.compile(r"\bHit \d+/\d+ PCs\b"), "PC-coverage stat"),
    (re.compile(r"\b\d+ distinct PCs\b"), "PC-coverage stat"),
    (re.compile(r"\b\d+ PCs\b"), "PC-coverage stat"),
    (re.compile(r"\bPCs (the )?probe\b", re.IGNORECASE), "PC-coverage stat"),
    (re.compile(r"\bthe probe hit\b", re.IGNORECASE), "PC-coverage stat"),
    (re.compile(r"\bcoverage trace\b"), "coverage narrative"),
    (re.compile(r"\bhits during\b", re.IGNORECASE), "coverage narrative"),
    # RE-tool narrative — "dasm misreads as", "the disassembler treats
    # X as", "Ghidra reads X". Belongs in internal_notes if at all;
    # otherwise just state the opcode/encoding directly.
    (re.compile(r"\bdasm (misread|reads as|treats|flags)", re.IGNORECASE),
     "RE-tool narrative"),
    (re.compile(r"\bdisassembler (misread|reads as|treats|flags|shows)",
                re.IGNORECASE), "RE-tool narrative"),
    (re.compile(r"\bthe disassembler shows\b", re.IGNORECASE),
     "RE-tool narrative"),
    (re.compile(r"\bopcode dasm\b", re.IGNORECASE), "RE-tool narrative"),
    # Corpus / tune-specific behavior — describing what a particular
    # corpus tune does at this address belongs in internal_notes (the RE
    # journal), not in role/notes. Names: T11/T16/T17/T01..T20, plus
    # specific tune titles (.GLOW, .AUTOMATAS, .HIVE, .MATSAM,
    # .MONDAY, .RAGNAROK).
    (re.compile(r"\bT\d{2}(?:/T\d{2})+\s+(?:corpus\s+)?tunes?\b"),
     "corpus-tune leak"),
    (re.compile(r"\.(?:AUTOMATAS|GLOW\s*WORM|HIVE|MATSAM|MONDAYNIGHT|"
                r"RAGNAROK|GLOW)\b"),
     "corpus-tune title"),
    # RE-history narrative — "Originally flagged X", "Earlier interpretation",
    # "Initially classified as", "Previously thought" describe what the
    # RE pass said before it was corrected. The current annotation should
    # describe the actual state, not its own history. RE history belongs
    # in internal_notes / git log.
    (re.compile(r"\bOriginally\s+(?:flagged|classified|interpreted|"
                r"thought|believed|read)", re.IGNORECASE),
     "RE-history narrative"),
    (re.compile(r"\bEarlier\s+(?:interpretation|interpretation\s+of|"
                r"name|annotation|version)", re.IGNORECASE),
     "RE-history narrative"),
    (re.compile(r"\bInitially\s+(?:flagged|classified|thought|read)",
                re.IGNORECASE),
     "RE-history narrative"),
    (re.compile(r"\bPreviously\s+(?:flagged|classified|thought|read|"
                r"named)", re.IGNORECASE),
     "RE-history narrative"),
    # Cross-tune / preframr parity references — these describe the
    # external Python player + corpus validation, not the binary itself.
    (re.compile(r"\bcross[- ]tune\s+(?:player\s+)?parity\b", re.IGNORECASE),
     "cross-tune / preframr reference"),
    (re.compile(r"\bpreframr\b"), "preframr reference"),
    (re.compile(r"\bthe static dis(asm|assembly)\b", re.IGNORECASE),
     "RE-tool narrative"),
    (re.compile(r"\bstatic disasm of\b", re.IGNORECASE),
     "RE-tool narrative"),
    # Cross-annotation narrative ("X is referenced in Y's annotation
    # as 'Z'"). The annotation system is the canonical source; quoting
    # one entry inside another is RE-meta and rots when either side
    # changes. Use plain "called from Y" / "invoked from Y" instead.
    (re.compile(r"\bis referenced in\b.{0,40}\bannotation\b", re.IGNORECASE),
     "cross-annotation narrative"),
    (re.compile(r"\bin .{0,30}'s annotation\b", re.IGNORECASE),
     "cross-annotation narrative"),
    # Xref narrative — "the single reference at X", "the two
    # references at X". The graph-derived reachability block carries
    # this now; prose mentions are stale or redundant.
    (re.compile(r"\bthe (single|one|two|three|\d+) references? at\b",
                re.IGNORECASE), "xref narrative"),
    (re.compile(r"\binbound reference\b", re.IGNORECASE), "xref narrative"),
    (re.compile(r"\binbound xref\b", re.IGNORECASE), "xref narrative"),
    (re.compile(r"\bare screen[- ]text\b", re.IGNORECASE),
     "xref-tautology variant"),
    (re.compile(r"\bis screen[- ]text\b", re.IGNORECASE),
     "xref-tautology variant"),
    (re.compile(r"\bbyte-coincidence\b", re.IGNORECASE),
     "RE-forensics jargon"),
    (re.compile(r"\bapparent (callers|references)\b", re.IGNORECASE),
     "xref forensics"),
    (re.compile(r"\b(matched|matching|spurious|coincidental) references\b",
                re.IGNORECASE), "xref forensics"),
    (re.compile(r"\breferences? lie in\b", re.IGNORECASE),
     "xref forensics"),
    (re.compile(r"\bnot real code\b", re.IGNORECASE), "xref forensics"),
    # "no real callers" / "no static callers" duplicates the graph-
    # derived reachability block that emit_defmon_source.py writes
    # automatically. Stop authoring it in prose.
    (re.compile(r"\bno (real|static) callers?\b", re.IGNORECASE),
     "xref narrative (graph-derived)"),
    (re.compile(r"\bnever executed\b", re.IGNORECASE),
     "coverage narrative"),
    (re.compile(r"\bnever fires\b", re.IGNORECASE), "coverage narrative"),
    (re.compile(r"\bnever observed\b", re.IGNORECASE),
     "coverage narrative"),
    (re.compile(r"\bnot reached at runtime\b", re.IGNORECASE),
     "coverage narrative"),
    (re.compile(r"\bunder harness phases\b", re.IGNORECASE),
     "harness narrative"),
    (re.compile(r"\bdecoded as opcode\b", re.IGNORECASE),
     "RE-tool narrative"),
    (re.compile(r"\bstatic byte[- ]scanner\b", re.IGNORECASE),
     "RE-tool narrative"),
    (re.compile(r"\(documentary\)", re.IGNORECASE),
     "annotation-meta apology"),
    (re.compile(r"\bTBD\b"), "annotation-meta TBD"),
    (re.compile(r"\bTODO\b"), "annotation-meta TODO"),
    (re.compile(r"\bFIXME\b"), "annotation-meta FIXME"),
    # Annotation-meta narrative — the entry apologising for its own
    # existence rather than describing the code. These belong in the
    # commit message of the entry that adds the parent block, or
    # nowhere at all.
    (re.compile(r"explicit \[region\] for orphan-scan", re.IGNORECASE),
     "annotation-meta apology"),
    (re.compile(r"\balready covered by .{0,80}— explicit \[region\]",
                re.IGNORECASE), "annotation-meta apology"),
    (re.compile(r"\balready documented in .{0,80}internal-label map",
                re.IGNORECASE), "annotation-meta apology"),
    (re.compile(r"this is its own \[region\] entry so the probe",
                re.IGNORECASE), "annotation-meta apology"),
    (re.compile(r"annotation retained for (narrative|orphan)",
                re.IGNORECASE), "annotation-meta apology"),
    # Recursive phrasing — a copy-paste accident that produced
    # "Reached only as a reachable only through ...".
    (re.compile(r"reached only as a reachable only", re.IGNORECASE),
     "recursive phrasing"),
    # Tautology: "X is a screen-text inside the disk-menu paint band,
    # not an executable target." — repeated near-verbatim across many
    # entries. The canonical replacement is
    # "Unreachable: only inbound reference is a data byte inside <name>."
    (re.compile(r"but [a-z_]+ is (a )?(screen[- ]text|disk-menu paint)",
                re.IGNORECASE), "screen-text-caller tautology"),
    # Paraphrase variants of the same tautology — every new phrasing
    # ("screen-RAM data", "screen-text byte", "no executable callers")
    # is the same fact expressed differently. The graph-derived
    # `code_in==0 ∧ apparent_in_from_data!=[]` predicate will replace
    # all of these in step 2; meanwhile, block the phrasings.
    (re.compile(r"\bscreen[- ]?RAM data\b", re.IGNORECASE),
     "screen-text-caller tautology"),
    (re.compile(r"\bscreen[- ]text byte\b", re.IGNORECASE),
     "screen-text-caller tautology"),
    (re.compile(r"\bno executable callers?\b", re.IGNORECASE),
     "screen-text-caller tautology"),
    (re.compile(r"\bsingle reference at .{1,80}? is (a )?screen",
                re.IGNORECASE), "screen-text-caller tautology"),
    # Other RE-process noise classes.
    (re.compile(r"\bCRITICAL FINDING\b"), "RE-narrative marker"),
    (re.compile(r"\bholds an unrelated\b", re.IGNORECASE),
     "wrong-slot description"),
    # "Do NOT reorder — offsets are load-bearing" is a constraint, not
    # a note. It belongs in a structured `constraints` field (step 4)
    # or in internal_notes pending that.
    (re.compile(r"\bload[- ]bearing\b", re.IGNORECASE),
     "constraint in prose (needs structured field)"),
    (re.compile(r"\bdo not reorder\b", re.IGNORECASE),
     "constraint in prose (needs structured field)"),
    # Pseudo-hex range refs
    (re.compile(r"\$[0-9A-Fa-f]{1,3}[xX]+"), "pseudo-hex range"),
    # Enum / arrow formatting — canonical is "$XX = label" and
    # "$XX → action" (with spaces). The compact register-assignment
    # idioms "A←$01", "X→$72,Y" (single uppercase letter on left)
    # stay compact and aren't flagged.
    (re.compile(r"\$[0-9A-Fa-f]{1,4}=[A-Za-z0-9_$]"),
     "enum-binding spacing (use `$XX = label`)"),
    (re.compile(r"\$[0-9A-Fa-f]{1,4}→(?!\s)"),
     "arrow spacing (use `$XX → ...`)"),
    (re.compile(r"[A-Za-z_]{2,}→\$[0-9A-Fa-f]"),
     "arrow spacing (use `label → $XX`)"),
    # REFUTED-class labels: should be moved to [refuted] section, not
    # propagated into prose.
    (re.compile(r"\bREFUTED_[a-z_]+"), "refuted-name leak"),
    (re.compile(r"\bREFUTED\b"), "refuted-class jargon"),
]


def find_hits(annotations: dict) -> list[tuple[str, str, str, str]]:
    """Return [(addr_text, field, label, excerpt), ...]."""
    hits: list[tuple[str, str, str, str]] = []
    for addr, body in sorted(annotations.items()):
        for field in CHECK_FIELDS:
            val = body.get(field, "")
            if not isinstance(val, str) or not val:
                continue
            for pat, label in BANNED:
                m = pat.search(val)
                if m:
                    start = max(0, m.start() - 30)
                    end = min(len(val), m.end() + 30)
                    excerpt = val[start:end].replace("\n", " ")
                    addr_text = f"${addr:04X}"
                    hits.append((addr_text, field, label, excerpt))
                    break  # one finding per field per entry is enough
    return hits


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--max-show", type=int, default=30)
    args = ap.parse_args(argv)

    annotations = load_annotations(ANNOTATIONS)
    hits = find_hits(annotations)
    n_ann = len(annotations)

    if not hits:
        print(f"check_no_re_narrative: OK — none of {n_ann} annotations "
              f"contain RE-process narrative or pseudo-hex in "
              f"{sorted(CHECK_FIELDS)}.")
        return 0

    print(f"check_no_re_narrative: {len(hits)} prose-field entries "
          f"contain banned content (move to evidence/internal_notes "
          f"or rewrite as semantic prose):")
    by_label: dict[str, list] = {}
    for addr, field, label, excerpt in hits:
        by_label.setdefault(label, []).append((addr, field, excerpt))
    for label, items in sorted(by_label.items(), key=lambda x: -len(x[1])):
        print(f"\n  [{len(items)}] {label}:")
        for addr, field, excerpt in items[:args.max_show]:
            print(f"     {addr}.{field}: ...{excerpt}...")
        if len(items) > args.max_show:
            print(f"     ... +{len(items) - args.max_show} more")
    print()
    print("`evidence` / `internal_notes` are exempt — use them for "
          "RE-process narrative and probe artifacts.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
