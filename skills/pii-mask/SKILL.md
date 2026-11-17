---
name: pii-mask
description: >-
  Mask personal data (PII) in a file or pasted text with a three-agent pipeline: a masker that makes the
  changes, a tester that checks the masked copy on its own, and an auditor that compares it against the
  original and confirms nothing personal is left. It never repeats or discusses any of the PII it finds.
  Use this whenever the user wants to mask, redact, anonymize, de-identify, scrub, sanitize or hide
  personal details (names, phone numbers, emails, addresses, Aadhaar, PAN, card or bank numbers, dates of
  birth, IDs, IPs) in a .txt, .md, .csv, .xlsx, .docx, .pdf, .json, log or code file, or in pasted text.
  Also use it when they want to share a dataset, log or document safely, or prepare data for DPDP/GDPR
  compliance, even if they never say "PII".
argument-hint: "<file path(s) or pasted text>"
license: MIT
---

# /pii-mask

You mask personal data in what the user gives you and prove the result is clean. The work is split across
three sub-agents, each working alone. A masker cannot reliably judge its own blind spots, so a second pair
of eyes on the output and a third comparing it against the original catch what the first one misses.

## Privacy rules

These rules are the whole point of the skill. The user is trusting you with data about other people.

- **Never repeat PII anywhere the user or others can see it:** chat, reports, agent prompts, agent
  answers, shell commands, file names or commit messages. Refer to an item only by **type and location**,
  for example "PHONE at row 14, col 3" or "NAME in paragraph 6". A masked preview such as `P***** T*****`
  is fine, because that is the published form.
- **Don't discuss the people in the data.** If the user asks "whose number was that?" or "what name was
  on line 4?", decline politely. Explain that the skill keeps those details private and the original file
  is still with them, unchanged. Don't confirm or deny guesses either ("is it Rahul?"), because a yes or
  no leaks as much as the value would.
- **Never modify the original file.** Write a masked copy beside the other outputs.
- **Never create a key or mapping file** that links original values to their masks. A file like that is a
  copy of the PII.
- **The orchestrator doesn't read the data.** You (the main session) pass file paths. Only the sub-agents
  open the file. The less the data passes through the conversation, the less can leak.
- **Be honest about what this guarantees.** The model has to read the data in order to mask it. The skill
  ensures the outputs and the conversation don't contain it. It doesn't make the data invisible to the
  model.

## Tools

The script `scripts/pii_tool.py` (in this skill's folder) finds pattern-shaped PII the same way every
time. It covers emails, phone numbers (Indian, international, US), Aadhaar, PAN, card numbers (Luhn
check), SSN, IP addresses, UPI IDs, profile URLs, labeled IDs (passport, account, voter ID, employee ID
and similar), dates of birth, and table columns whose header means name, address or DOB. It **never
prints raw values**. It prints only the type, the location and the masked form, so its output is safe to
show.

```
python -I <skill>/scripts/pii_tool.py scan <file>                        # exit 1 = PII found
python -I <skill>/scripts/pii_tool.py mask <in> <out> --terms <terms.tsv>
python -I <skill>/scripts/pii_tool.py text <in> <run>/.work/<name>.txt     # readable text of xlsx/docx/pdf
python -I <skill>/scripts/pii_tool.py compare <original> <masked>         # changed locations (per column for tables), no values
python -I <skill>/scripts/pii_tool.py clean <run>                         # delete <run>/.work
```

**Keep the run free of permission prompts.** Every new shell command makes Claude Code ask the user for
approval, and a run that asks a dozen times is a hassle. So sub-agents should only:

- run commands in exactly the form above, with `<skill>` as this skill's folder, written with forward
  slashes and starting `python -I`, so one permission rule can cover them all;
- use Read to look at files (`text` first, for formats Read can't open);
- use Write for `terms.tsv` and `AUDIT.md`. Write creates folders itself, so don't run `mkdir`.

Don't use `cat`, `grep`, `rm`, `mkdir`, `cd`, `&&` chains, or one-off Python. If something truly can't be
done with these commands, say so in the reply and let the orchestrator decide; don't improvise.

The terms file holds the things only a reader can recognize. Each line is `TYPE<TAB>value`, where TYPE is
`NAME`, `ADDRESS` or `OTHER`. It is the only place raw values are written. It lives in the run's `.work/`
folder and is deleted at the end. Agents can also `import pii_tool` (add the scripts folder to
`sys.path`) to reuse `mask_name`, `mask_phone` and the other mask functions, but only as a last resort for
a format the commands can't handle, because each one-off script means another permission prompt.
Letter-spaced names (`J O H N`) can go straight into the terms file. The script handles them.

**Supported formats:** `.txt .md .csv .tsv .json .log .xml .yaml .html`, code and other text files,
`.xlsx`, `.docx` and `.pdf`.

**The masked copy is always in the same format as the input.** A `.pdf` comes back as a `.pdf`, an
`.xlsx` as an `.xlsx`, a `.docx` as a `.docx`, a `.csv` as a `.csv`, and so on, with the layout,
styling, sheets, formulas and line endings kept. `mask` refuses an output name whose extension differs
from the input's, and `compare` flags a format mismatch. Never convert the file to another format to
make masking easier.

How each format keeps its look:

- **PDF:** each personal value is redacted out of the PDF itself (so it can't be copied or recovered
  from the file), and its masked form is written back in the same spot, at the same size and colour, in
  a standard font that matches it closely (sans or serif, bold or regular). Backgrounds, lines, images
  and all other text stay exactly where they were. Clickable links whose target holds PII (mailto:,
  profile URLs) are removed. Metadata (author, title), bookmarks, comments and form fields are masked,
  and hidden text, XMP metadata, attachments and scripts are stripped. If the redaction would move any
  kept text, `mask` refuses and writes nothing. It needs PyMuPDF (`pip install pymupdf`).
- **XLSX / DOCX:** values are changed cell by cell and run by run, so formatting, formulas and sheets
  stay as they were.
- **Text formats:** the same file with only the PII changed, with the original line endings.

**What can't be masked in place:** a scanned PDF page or an image with no text layer (`scan`, `text`
and `mask` flag it as `NO TEXT LAYER`), and photos or signatures embedded as images, which are kept as
they are (`compare` reports the image count). Tell the user about either, and don't report the file as
clean if a page holds unmasked PII in an image.

## Masking style: partial masks

| Type | Example result |
|---|---|
| Name | `P***** T*****` (first letter of each word) |
| Phone | `+91 98******10` (country code, first 2 and last 2 digits) |
| Email / UPI | `p***@gmail.com` (first letter and the domain) |
| Aadhaar | `**** **** 0123` |
| PAN / bank account / driver's license / passport / labeled IDs | `******234F` (last 4; IDs under 8 characters keep 2) |
| Card | `**** **** **** 1111` |
| SSN | `***-**-6789` |
| Date of birth | `**/**/1995` or `**-**-95` (year kept) |
| IP address | `192.168.*.*` |
| Address | `** P*** S*, Kolkata ******` (city kept, street and PIN masked) |
| ZIP / PIN code column | `*****` (fully masked) |
| Profile URL | `linkedin.com/in/r*********` |

In a table (`.csv`, `.tsv`, `.xlsx`), the script reads the header row. It masks whole columns whose header
means a person's name (`Name`, `Person Name`, `customer_name`), an address, a ZIP or PIN code, a date of
birth, or an ID (`Drivers License`, `SSN`, `Passport No`, `Account Number`). It leaves columns that only
describe a document alone (`License Issue Date`, `License State`). Spreadsheet date cells in a DOB column
become text such as `**/**/1984`, because a date cell can't hold stars. Check `compare`'s per-column
summary: each changed column should be a PII column.

The same original value always gets the same mask, so the data still reads consistently. Don't mask
things that aren't about a person: amounts, product names, order dates, company names used as a
business, version numbers, formulas, or shared business inboxes (`support@`, `info@`, `sales@`). The
script already skips those inboxes. A person's own work email still gets masked. Over-masking ruins the
file for the user, and the auditor will fail it. Keep the file's formatting as it was. The script keeps
the original line endings.

## Steps

Each run writes everything to `.pii-masked/<YYYY-MM-DD>-<file-stem>/` in the current folder, and touches
nothing else:

- `<stem>.masked.<ext>`: the masked copy, with the **same extension as the input**
  (`resume.masked.pdf` for `resume.pdf`)
- `AUDIT.md`: the report (types, counts, locations and verdicts only, never values)
- `.work/`: scratch files, deleted at the end

If the input's file name itself contains PII (for example a person's name), use a neutral stem such as
`resume` or `data` for the run folder and the masked copy, and keep the original extension.

For **pasted text**, write it to `.work/input.txt` and treat that as the input. The final masked text can
also be shown in chat, since masked text is safe.

### 1. Masker

Start one sub-agent. Give it: the input path, the output path, the `.work/` path, the script path, and the
masking table and privacy rules above. Its job:

1. Read the whole input. For a big table, read the header and a good sample, and check every column.
   For a PDF, read the `text` output (it is the exact line text `mask` works on, so terms written from it
   will match) and also Read the PDF itself to see what's on the page, including any photo.
2. List what the patterns can't catch. This covers names (including first names on their own, surnames,
   nicknames, initials with a surname, letter-spaced or uppercase variants, and names inside signatures,
   greetings and email bodies), street addresses, and any other personal detail that identifies someone.
   Write these to `.work/terms.tsv`.
3. Run `mask`, then `scan` the output, then read the output itself. Fix anything still visible, by adding
   terms or writing a small script that uses the mask functions, and re-run until both are clean.
4. Reply with counts by type, and with any locations it was unsure about (no values).

### 2. Tester

Start one sub-agent that gets **only the masked file**, not the original. It tests the output the way an
outsider would see it, so it must not know what the answers are. It:

- Runs `scan` on the masked file.
- Reads the masked file end to end and asks whether anyone could identify a real person from it. It looks
  for leftover names, partial addresses, emails, signatures, IDs, and combinations like "the only
  cardiologist at X hospital".
- Checks that the file still works: it is in the same format as the input (a PDF is still a PDF, and so
  on), it opens, the table shape is intact, formulas and non-personal values look untouched, and nothing is
  garbled. For a PDF it Reads the masked PDF to see the pages: the layout should look like an ordinary
  document, with masked values sitting in place and not overlapping other text.
- Answers PASS or FAIL, with each problem as type and location only.

On FAIL, send the masker the tester's list (types and locations), let it fix the file, and run the tester
again. Allow at most two fix rounds.

### 3. Auditor

Start one sub-agent that gets **both the original and the masked file**. It is the final check, and it is
strict. It:

- Goes through the original and lists every PII item for itself, without relying on the masker's list.
- Confirms each one is masked in the output, and masked consistently (the same person always gets the same
  mask).
- Confirms nothing that isn't PII was changed (amounts, dates that aren't birthdays, product names,
  formulas, structure). Run `compare`: every changed location it lists should hold PII, the format must
  be the same, and the structure, page count and line endings should match.
- Confirms that `AUDIT.md` (if a draft exists), the agents' answers and the file names contain no raw
  values.
- Answers **CLEAN** or **NOT CLEAN**, with each remaining issue as type and location only.

On NOT CLEAN, run one more masker fix, then audit again. If it still fails, report the failure honestly,
including where the problem is. Never call a file clean when the auditor didn't.

### 4. Finish

1. Write `AUDIT.md`:
   - input and output file names
   - items masked, by type, with counts
   - the tester's verdict and the auditor's verdict
   - fix rounds used
   - limitations (image-only pages, photos or signatures kept as images, and for a PDF that masked
     values use a standard font close to the original)
   - the reminder that partial masks keep a first letter or the last digits, which can still identify
     someone in a small group; offer full redaction if that matters
   - for tables: if the columns left unmasked (city, state, exact dates) combine with the partial masks
     to narrow a row down to one person, say so and suggest fully masking the ID columns or reducing
     those dates to the year

   No values anywhere in it.
2. Delete `.work/` (it contains the terms file) with the `clean` command.
3. Tell the user in chat:
   - what was masked (types and counts)
   - the tester and auditor verdicts
   - where the masked file and `AUDIT.md` are
   - any limitations
   - if a `~$` lock file sits next to the masked copy, the file is open in Excel; that lock file
     shouldn't be shared with it

   Show no PII.
