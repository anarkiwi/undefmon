# defMON user guide

A music tracker for the Commodore 64. defMON is a "live" tracker — you
edit while the tune plays and hear the change on the next pattern step.

This guide covers concepts, a step-by-step walkthrough for a simple
tune, and a complete keychord reference for every edit region.

---

## 1. Concepts

defMON splits a tune into three editor regions that share one screen:

| Region   | What you edit                          | Key to enter |
|----------|----------------------------------------|--------------|
| seqED    | the **pattern** (per-step notes)       | RUNSTOP from seqLIST |
| seqLIST  | the **arranger** (song-order of patterns) | RUNSTOP from seqED |
| sidTAB   | the **sound programs** (synth patches) | LEFTARROW (top-left of C64 keyboard) |

A C64 SID has 3 voices. defMON exposes each voice's pattern + arranger
column side-by-side; you can edit a step on any voice without switching
modes. With 2SID stereo enabled (CTRL+SHIFT+LEFTARROW) you get voices
4-6 on a second SID chip.

**Pattern:** 32 steps. Each step holds, per voice:

- a **note** (Z…M for the chromatic scale, like a piano row)
- **two sidCALL slots** that hold sidTAB-row hex IDs (`$00-$FF`).
  sidCALL1 sets the patch when the note starts; sidCALL2 layers a
  second effect on top (e.g. vibrato, filter sweep).
- a **speed/duration** nibble that controls how long the step holds
  before the player advances.

**Arranger (seqLIST):** the playback order. Each row references a
pattern number per voice; the player walks rows top-to-bottom and
plays the referenced patterns. A row with V0 = `$FF` is a JUMP — V1
holds the target row, V2 holds the repeat count (`$00` = infinite
loop).

**sidTAB:** a library of sound programs, one per row (typical tune
has 16-64 rows). Each row's 30 hex digits encode every SID register
the synth needs — waveform, envelope, pulse width, filter cutoff,
slides. You "play" a sidTAB row by putting its row number in a step's
sidCALL slot.

**The player IRQ runs at ~42 Hz** (CIA-1 Timer-A), faster than the
50 Hz PAL frame. Each tick the cascade walks each voice's active
sidTAB row, applies the next column's effect, advances counters.

---

## 2. Quick start: building a 4-bar tune

Goal: a 4-bar loop with a square-wave lead on V0, a triangle bass on
V1, and a noise hihat on V2. We'll define 3 sidTAB patches, write one
pattern, and play it in a loop.

You're at the title screen after loading `defmon-20201008.d64`. The
cursor is in seqED on V0, step 0.

### Step 1 — Define the lead sound (sidTAB row 1)

1. Press **LEFTARROW** to open sidTAB. Cursor lands at WG_wave (col 9).
2. Press **CRSRUD** (down arrow) to navigate to row 1 (or it's already there).
3. Type `4` — sets WG_wave = `40` → pulse waveform (`+4`).
4. The cursor auto-advances right. You're now at WG_gate.
5. Type `0`, `1` — sets WG_gate = `01` → gate-on (`+1`).
6. Cursor now at **AD**. Type `0`, `8` — Attack=0 (instant), Decay=8 (medium).
7. Cursor at **SR**. Type `C`, `0` — Sustain=C (loud), Release=0 (short).
8. Cursor at **TR** (transpose). Type `0`, `0` — no transpose.
9. Cursor at **AF** (finetune). Type `0`, `0`.
10. Cursor at **PW** (pulse width). Type `8`, `0` — width `$800` ≈ 50% duty cycle.
11. Cursor at **PS** (pulse sweep). Type `0`, `0` — no sweep.
12. Cursor at **RE** (resonance). Type `0`, `0`.
13. Cursor at **FV** (filter type). Type `0`, `0` — filter off.
14. Cursor at **CP** (cutoff offset). Type `0`, `0`.
15. Cursor at **ACID** (cutoff). Type `0`, `0`, `0`, `0`.

Row 1 is now a pulse-wave lead.

### Step 2 — Define the bass sound (sidTAB row 2)

1. **CRSRUD** down to row 2.
2. Type `1` — WG_wave = `10` (triangle, `+1`).
3. Type `0`, `1` — gate-on.
4. Type `0`, `4` — Attack=0, Decay=4 (slower attack body).
5. Type `8`, `8` — Sustain=8, Release=8 (sustained body, long tail).
6. Skip TR/AF/PW (triangle ignores PW; type `0` six times to pass through).
7. Type `0`, `0` for PS, then `0`, `0` for RE.
8. Type `0`, `0` for FV/CP, then `0`, `0`, `0`, `0` for ACID.

### Step 3 — Define the hihat (sidTAB row 3)

1. **CRSRUD** down to row 3.
2. Type `8` — WG_wave = `80` (noise, `+8`).
3. Type `0`, `1` — gate-on.
4. Type `0`, `2` — Attack=0, Decay=2 (very short).
5. Type `0`, `0` — Sustain=0, Release=0 (percussive only).
6. Press **SPACE** through TR..ACID to leave defaults (`-` cells).

### Step 4 — Lay down the pattern

1. Press **LEFTARROW** again to return to seqED.
2. Cursor lands on V0, step 0. Press **CTRL+G** twice to jump to step 0,
   voice 0 if you're not already there.
3. **Assign sidCALL1 = 01 on V0 step 0**: hold **C=** (Commodore key)
   and type `0`, `1`. The cell shows `01` in the sidCALL1 column.
4. **Assign a note**: tap **N** (the C64 keyboard letter row maps
   Z-M to chromatic notes; N = A in the lower octave). Cursor
   auto-advances down to step 1.
5. **Step 8 (next quarter beat)**: press **CRSRUD** until you're at
   step 8 (or press **CTRL+H** to jump). Hold **C=**, type `0`, `1`,
   then tap **B** (G note). Auto-advance.
6. Repeat at steps 16 and 24 with notes **V** (F) and **M** (B). You
   now have a simple 4-note lead.

### Step 5 — Add bass on V1

1. Press **CRSRLR** to switch focus to V1 step 0 (the cursor walks
   through V0's 4 columns then jumps to V1).
2. Hold **C=**, type `0`, `2` (sidCALL1 = `02` — the triangle bass).
3. Tap **Z** (C note, lowest octave). Auto-advance.
4. Move to V1 step 16; hold **C=**, type `0`, `2`, then tap **C** (E).

### Step 6 — Add hihat on V2

1. **CRSRLR** to V2 step 0.
2. Hold **C=**, type `0`, `3`.
3. Tap **SPACE** instead of a note — `SPACE` writes "no note" but
   keeps the sidCALL active, so the hihat triggers but doesn't carry
   pitch.
4. Repeat at every even step (2, 4, 6, ...) for a 16th-note hihat
   pattern. Speeds this up with **CTRL+W** (write-loop super-command,
   see §7).

### Step 7 — Set the song order

1. Press **RUNSTOP** to switch focus to seqLIST (right side of the
   screen).
2. Cursor on V0 row 0. Type `0`, `0` — references pattern `$00` (the
   one you just edited).
3. Repeat on V1 and V2 rows 0.
4. To loop forever: on V0 row 1 type `F`, `F` (jump marker). On V1
   row 1 type `0`, `0` (jump target = row 0). On V2 row 1 type `0`,
   `0` (repeat count `00` = infinite).

### Step 8 — Play

- **F3** = play from song start
- **F1** = play from cursor (useful when iterating)
- **F5** = toggle follow-play (cursor tracks the playhead)
- **F7** = stop

### Step 9 — Save

1. **LSHIFT+X** opens the disk menu.
2. **S** prompts for a filename.
3. Type the name (max 15 chars), **RETURN** to save.

---

## 3. Global keys (work in every mode)

| Chord                          | Action |
|--------------------------------|--------|
| **F1**                         | Play from cursor |
| **F3**                         | Play from song start |
| **F5**                         | Toggle follow-play |
| **F7**                         | Stop playback |
| **SHIFT+F1**                   | Multispeed ×1 (~50 Hz player tick) |
| **SHIFT+F3**                   | Multispeed ×2 (~100 Hz) |
| **SHIFT+F5**                   | Multispeed ×4 (~200 Hz) |
| **SHIFT+F7**                   | Multispeed ×8 (~400 Hz sub-frame) |
| **RUNSTOP**                    | Toggle focus seqED ↔ seqLIST |
| **LEFTARROW**                  | Open sidTAB (from seqED/seqLIST), exit (from sidTAB) |
| **LSHIFT+X**                   | Open disk menu |
| **[** (SHIFT+`:`)              | Mute / unmute voice 1 |
| **]** (SHIFT+`;`)              | Mute / unmute voice 2 |
| **=**                          | Mute / unmute voice 3 |
| **CTRL+RETURN**                | Cancel a staged super-command |
| **CTRL+G**                     | Cursor to step 0 |
| **CTRL+G** twice (CTRL+G+G)    | Cursor to step 0, voice 0 (top-left) |
| **CTRL+H / J / K**             | Cursor jump within the current voice |

---

## 4. seqED — pattern editor

Pattern cells live at `$1F00` + voice×4 + step×12 (3 voices × 4 bytes
per voice per step). The cursor's *visible column* is one voice's
note slot; the modifier you hold when typing selects WHICH sub-field
of that voice receives the keystroke.

### 4.1 Navigation

| Chord                  | Action |
|------------------------|--------|
| **CRSRUD** (down)      | Step + 1 (cursor down) |
| **SHIFT+CRSRUD**       | Step − 1 (cursor up) |
| **CRSRLR** (right)     | Voice column + 1; wraps after V2 to V0 step+1 |
| **SHIFT+CRSRLR**       | Voice column − 1 |
| **CTRL+G**             | Step := 0 |
| **CTRL+G** then **G**  | Step := 0, voice := 0 |
| **CTRL+H**             | Step := halfway (16) |
| **CTRL+J**             | Step := next quarter (8/16/24) |
| **CTRL+K**             | Step := pattern end |

### 4.2 Note input

The bottom two rows of the C64 alphabet keys form a two-octave
chromatic keyboard:

| Key | Note (lower octave) | Key | Note (upper octave) |
|-----|---------------------|-----|---------------------|
| `Z` | C                   | `Q` | C+1 |
| `S` | C#                  | `2` | C#+1 |
| `X` | D                   | `W` | D+1 |
| `D` | D#                  | `3` | D#+1 |
| `C` | E                   | `E` | E+1 |
| `V` | F                   | `R` | F+1 |
| `G` | F#                  | `5` | F#+1 |
| `B` | G                   | `T` | G+1 |
| `H` | G#                  | `6` | G#+1 |
| `N` | A                   | `Y` | A+1 |
| `J` | A#                  | `7` | A#+1 |
| `M` | B                   | `U` | B+1 |

Pressing a note key writes the note + sets GATE_N (bit 4 of the
step's flag byte). Cursor auto-advances down by 1 step. To enter a
note WITHOUT advancing, hold SHIFT.

| Bare-key                  | Action |
|---------------------------|--------|
| **note letter**           | Write note, GATE_N=1, advance step |
| **SPACE**                 | Clear note (GATE_N=0); auto-advance |
| **INSTDEL**               | Clear note (GATE_N=0); DON'T advance |
| **`+`**                   | Octave + 1 (cursor stays) |
| **`-`**                   | Octave − 1 |

### 4.3 sidCALL input (per voice, per step)

sidCALL slots address the sound program from sidTAB. Each slot holds
2 hex digits; defMON uses a "modifier-held" pattern so 2 digits land
in one cell:

| Chord (held)                | What it writes |
|-----------------------------|----------------|
| **C= + digit + digit**      | sidCALL1 (2 hex digits) |
| **C= + SHIFT + digit + digit** | sidCALL2 (2 hex digits) |

Hold the modifier, type both digits, release. The cell lights up in
its sidCALL column. sidCALL2 layers a second effect on top (e.g. a
vibrato or filter sweep) that runs in parallel with sidCALL1.

To clear a sidCALL: hold the same modifier and type `SPACE`.

### 4.4 Speed / duration

The step's "speed" nibble (low 4 bits of the flag byte) is the
inter-event duration. Smaller = faster.

| Chord                  | Action |
|------------------------|--------|
| **SHIFT + hex digit**  | Write speed nibble (0..F) |
| **SHIFT + SPACE**      | Clear speed |

### 4.5 Mode-transition

| Chord            | Action |
|------------------|--------|
| **RUNSTOP**      | Switch focus to seqLIST |
| **LEFTARROW**    | Open sidTAB |

---

## 5. seqLIST — arranger

Each row references a pattern number per voice. The player walks rows
top-to-bottom; a row with V0 = `$FF` is a JUMP (see §1).

| Chord                 | Action |
|-----------------------|--------|
| **CRSRUD**            | Row + 1 |
| **SHIFT+CRSRUD**      | Row − 1 |
| **CRSRLR**            | Voice column + 1 |
| **SHIFT+CRSRLR**      | Voice column − 1 |
| **hex digit + hex digit** | Write pattern number (2 nibbles, auto-advance to next nibble within the cell) |
| **`<`** (SHIFT+,)     | Pattern number − 1 (decrement current cell) |
| **`>`** (SHIFT+.)     | Pattern number + 1 |
| **SPACE**             | Clear cell |
| **INSTDEL**           | Clear cell |
| **RUNSTOP**           | Switch focus to seqED |
| **LEFTARROW**         | Open sidTAB |
| **CTRL + N**          | Clone current cell to next empty row (super-command) |

To create a JUMP row: on V0 type `FF`, on V1 type the target row
number, on V2 type the repeat count (`00` = infinite loop).

---

## 6. sidTAB — sound programs

Each row holds 30 hex digits arranged as 13 logical fields. The
cursor enters at WG_wave (column 9, not JP), and wraps right
through all columns. Typing a hex digit auto-advances by one cell.

### 6.1 Column reference

| Column      | Cells | Cols  | Semantics |
|-------------|------:|-------|-----------|
| **JP**      | 2     | 3-4   | Step jump (target row). SPACE deletes |
| **DL**      | 2     | 6-7   | Step delay: `00-7F` frames hold; `80-FF` = STop (silence). SPACE resets |
| **WG_wave** | 2     | 9-10  | Waveform — upper nibble: `+1` tri, `+2` saw, `+4` pulse, `+8` noise (sum any) |
| **WG_gate** | 2     | 11-12 | Lower nibble: `+1` gate, `+2` sync, `+4` ringmod, `+8`/`+9` test |
| **AD**      | 2     | 13-14 | Attack / Decay (Hi nibble = Attack 0-F, Lo = Decay 0-F) |
| **SR**      | 2     | 15-16 | Sustain / Release |
| **TR**      | 2     | 17-18 | Transpose: `00-7F` relative semitones up; `80-FF` absolute pitch override |
| **AF**      | 2     | 19-20 | Finetune / bend: `00-19` finetune; `21-7F` pitch up; `80-BF` bend up; `C0-FF` bend down |
| **PW**      | 2     | 22-23 | Pulse width: 12-bit `$YXY` encoding (`83` → PW $383) |
| **PS**      | 2     | 24-25 | Pulse sweep: `00-7F` left/down; `80-FF` right/up |
| **RE**      | 2     | 27-28 | Resonance hi-nibble; lo-nibble = channel filter-routing mask |
| **FV**      | 2     | 29-30 | Filter type: `10/90` lp, `20/A0` bp, `30/B0` lp+bp, `40/C0` hp, `50/D0` lp+hp, `60/E0` bp+hp, `70/F0` all |
| **CP**      | 2     | 31-32 | Cutoff offset: `00-7F` add; `80-FF` subtract |
| **ACID**    | 4     | 33-36 | Cutoff: `0000-7FFF` absolute; `8000-BFFF` slide up; `C000-FFFF` slide down |

### 6.2 Navigation + editing

| Chord                  | Action |
|------------------------|--------|
| **CRSRLR**             | Cursor right (one hex digit) |
| **SHIFT+CRSRLR**       | Cursor left |
| **CRSRUD**             | Row + 1 (scrolls when at the bottom of the visible window) |
| **SHIFT+CRSRUD**       | Row − 1 |
| **hex digit (0-9, A-F)** | Write digit; auto-advance right |
| **SPACE**              | Clear cell (restores `-` default) |
| **`.`** (PERIOD)       | Tab-right one full column |
| **`,`** (COMMA)        | Tab-left one full column |
| **F5**                 | Insert a new sidTAB row at the cursor |
| **`/`**                | Toggle the cell's "JP" semantic |
| **`<`** (SHIFT+,)      | Cursor highlight toggle (cosmetic; doesn't edit value) |
| **`>`** (SHIFT+.)      | Cursor highlight toggle |
| **LEFTARROW**          | Exit sidTAB (back to seqED/seqLIST) |
| **CLR/HOME**           | Exit to seqLIST |

### 6.3 sidTAB row programming pattern

The cascade ticks every player IRQ. Each row's `DL` column controls
how long the cascade lingers on this row before moving to the next:

- `DL = 00` → no hold; advance immediately
- `DL = 01..7F` → hold for N IRQs, then advance
- `DL = 80..FF` → STop — silence the voice, latch here

A typical patch:
- Row 0: WG_wave=`10` triangle, WG_gate=`01` gate, AD=`08`, SR=`C0`,
  DL=`02` hold 2 frames, JP=`00` (continue to next row)
- Row 1: TR=`02` transpose +2, PS=`80` slide pitch up, DL=`04`,
  JP=`00`
- Row 2: AF=`C5` bend down, DL=`FF` STop

The full sequence: trigger → hold triangle gate-on for 2 frames →
slide pitch up for 4 frames → bend down → silence.

---

## 7. Super-commands (CTRL + letter)

Super-commands are CTRL-prefixed chords that take a typed-digit
argument. Hold CTRL ACROSS the entire chord; releasing CTRL between
the prefix letter and the digit drops the chord into the regular
note/digit path.

| Chord                              | Action |
|------------------------------------|--------|
| **CTRL + W + hex + hex**           | Write current cell value into the next N cells (auto-fill loop). Args = lo/hi nibble of fill count. |
| **CTRL + S + digit**               | Set step duration (advance speed) |
| **CTRL + R + digit**               | Set CIA-1 Timer-A reload (master speed) |
| **CTRL + R + `.`**                 | Bump sub-frame count UP (1→2→4→8) |
| **CTRL + R + `,`**                 | Bump sub-frame count DOWN |
| **CTRL + Z + hex + hex**           | Zone — fill range with current value |
| **CTRL + G + hex**                 | Page-jump to step (0-F = 0/8/16/24 etc.) |
| **CTRL + RETURN + letter**         | Macro execute — letter selects macro |
| **CTRL + N**                       | Clone current cell to next empty (seqLIST only) |
| **CTRL + U**                       | Clear loop / undo super-command state |

### Speed-preset shortcuts (F1..F8 with SHIFT)

| Chord         | Action                          |
|---------------|----------------------------------|
| **SHIFT+F1**  | Speed preset 0 = 50 Hz (PAL VBL) |
| **SHIFT+F3**  | Speed preset 1 = 100 Hz          |
| **SHIFT+F5**  | Speed preset 2 = 200 Hz          |
| **SHIFT+F7**  | Speed preset 3 = 400 Hz ÷ 8 sub-frame |

---

## 8. Disk menu (SHIFT+X)

Opens a directory listing of the mounted disk. The disk menu is a
nested input loop — it suspends the main editor until you exit.

| Chord            | Action |
|------------------|--------|
| **CRSRUD**       | Move cursor down the file list |
| **SHIFT+CRSRUD** | Move cursor up |
| **RETURN**       | Load the file under the cursor |
| **L**            | Load by typed name (prompts for filename) |
| **S**            | Save current tune (prompts for filename) |
| **SHIFT+S**      | Save-overwrite (replaces existing slot) |
| **SHIFT+P**      | Pack-save (exomizer-compressed save) |
| **W**            | Legacy write (older save format) |
| **B**            | Back / page-up |
| **T**            | Save as throwaway (`_TS` slot) |
| **LSHIFT+R**     | Retry last operation on failure |
| **Y / N**        | Y/N confirm prompt response |
| **LEFTARROW**    | Exit disk menu (back to editor) |
| **RUNSTOP**      | Exit disk menu (alternate) |

### Filename rules

- Max 15 chars typed (defMON's own limit; CBM DOS allows 16).
- defMON prepends `.` to your typed name automatically.
- Underscore is not on the C64 matrix; use `@` instead. defMON
  encodes typed `@` as `]` in the on-disk filename.

---

## 9. Secondary disk mode (CTRL+`/` from sidTAB)

A separate sub-mode reachable only from sidTAB. Drives a typed
filename buffer for saving sidTAB-only programs. Mostly unused in
normal workflows.

| Chord            | Action |
|------------------|--------|
| **letters / digits** | Type characters into the secondary filename buffer |
| **CTRL + `.`**   | Octave + (in sidTAB context) |
| **CTRL + `,`**   | Octave − |
| **LEFTARROW**    | Exit secondary disk mode (back to sidTAB) |

---

## 10. Stereo (2SID) chords

Stereo mode enables a second SID chip at `$D420` (or another base
address). Voices 4-6 then live on the second chip.

| Chord                              | Action |
|------------------------------------|--------|
| **CTRL + SHIFT + LEFTARROW**       | Toggle stereo on / off |
| **CTRL + LEFTARROW**               | Switch chip view (SID#1 ↔ SID#2 arrangers) |
| **CTRL + SHIFT + UPARROW**         | Cycle SID#2 high byte (`$D4 → $D5 → $DE → $DF`) |
| **CTRL + C= + UPARROW**            | Adjust SID#2 low byte (+$20) |

With stereo on, voices 4-6 use the same pattern bank as 1-3 but their
own arrangers at `$6E00 / $6F00 / $7000`.

---

## 11. Things that aren't keychords

- **Multispeed beyond ×8** — defMON's player IRQ is CIA-1 Timer-A,
  not vblank. You can write a CIA reload directly via CTRL+R + digits
  for arbitrary tempos.
- **ScannerBoy sync** — toggled programmatically via `$DD01`, no
  chord. See `docs:scannerboysync` on the defMON wiki.
- **MIDI / SID-cart import** — not implemented in defMON.

---

## 12. Reference

- defMON wiki: https://defmon.vandervecken.com
- "defMONing 101" field guide: wiki page `docs:fieldguide`
- "defMONing 102" extended guide: wiki download `defmoning_102.rtf`
- Player API memory entry points: `$1000` init, `$1003` main_tick,
  `$1006` sub_frame, `$1522` player_init
