# The PII mask skill

Need to share a spreadsheet, a log or a support thread, but it's full of names, phone numbers and ID numbers? This
skill masks every piece of personal data in it, then has two more Claudes check the result before you get it back.
Free, MIT licensed, with no signup and no API key.

## The three agents

1. **The masker** reads the file and finds what only a reader can spot: names, nicknames, relatives, signatures and
   street addresses. It then runs a script that catches every pattern-shaped value the same way each time: phone
   numbers, emails, Aadhaar, PAN, card and bank numbers, SSNs, dates of birth, IPs, UPI IDs, passport, driver's
   license and employee IDs, and profile links. In spreadsheets and CSVs it also reads the header row, so whole
   columns like `Person Name`, `Drivers License`, `Zip Code` or `DOB` are masked without anyone listing them.
2. **The tester** sees **only the masked copy**, never the original. It reads the copy the way an outsider would and
   asks two questions. Could anyone still identify a real person from it? Does the file still work: same shape,
   formulas intact, nothing garbled? It answers PASS or FAIL.
3. **The auditor** compares the original with the masked copy. It lists every personal detail for itself, checks that
   each one is masked the same way everywhere, and fails the file if anything that *isn't* personal was changed.
   It answers CLEAN or NOT CLEAN.

If the tester or auditor finds a problem, the masker fixes it and the file is checked again. A file is never reported
as clean unless the auditor said so.

## What it looks like

| Before | After |
|---|---|
| `Call Kavya Menon on 98201 33445` | `Call K**** M**** on 98******45` |
| `kavya.menon82@example.com` | `k***@example.com` |
| `Aadhaar 4321 8765 2109` · `PAN BQSPS7781L` | `**** **** 2109` · `******781L` |
| `DOB: 14/07/1988` · `my DOB is 07-14-88` | `DOB: **/**/1988` · `my DOB is **-**-88` |
| `SSN 321-54-9876` · driver's license `TQ482915` | `SSN ***-**-9876` · `****2915` |
| `Flat 7B, Lake View Apartments, Koramangala, Bengaluru 560034` | `F*** 7*, L*** V*** A*********, K**********, Bengaluru ******` |
| `support@shop.in`, `Rs 3,499`, `order A-55821` | unchanged (not personal) |

*(All examples are made up.)*

## Privacy rules it follows

- **It never repeats your data.** It refers to items only by type and place, for example "PHONE at row 14", in
  chat, in the report and between agents.
- **It doesn't talk about the people in the file.** It won't say whose number it was, and it won't confirm or deny
  a guess.
- **Your original file is never changed.** No key file linking real values to their masks is ever saved, and the
  temporary list of names is deleted when the run ends.

## Install

Paste this into Claude Code:

```
https://github.com/Piyush-nr-tiwari/pii-mask-skill
Install this skill, then confirm /pii-mask works.
```

Or install it as a plugin:

```
/plugin marketplace add Piyush-nr-tiwari/pii-mask-skill
/plugin install pii-mask-skill@pii-mask-skill
```

Or copy `skills/pii-mask` into `~/.claude/skills/`. Open a new Claude Code session afterwards. The script needs
Python 3.10+. For Excel, Word and PDF files, also run `pip install openpyxl python-docx pymupdf`.

## Use

```
/pii-mask customers.xlsx
/pii-mask support_export.csv logs/app.log
/pii-mask   (then paste the text)
```

Turn on accept-edits mode first (Shift+Tab). Each file takes about 3–5 sub-agent calls, which count toward your
Claude plan's usage. Results go in `.pii-masked/<date>-<file>/`:

- the masked copy, in the same format as the file you gave it (PDF in, PDF out; Excel in, Excel out)
- `AUDIT.md`, which lists counts by type and both verdicts, never the values

**Fewer approval prompts:** the agents only ever run the skill's own script, so you can approve it once.
Add these lines to `~/.claude/settings.json` under `permissions.allow`, using your own home folder in the
path:

```json
"Bash(python -I C:/Users/YOU/.claude/skills/pii-mask/scripts/pii_tool.py *)",
"Read(~/.claude/skills/pii-mask/**)",
"Edit(**/.pii-masked/**)"
```

This is safe to pre-approve because the script refuses to write anywhere outside a `.pii-masked/` folder.

**File types:** `.txt .md .csv .tsv .xlsx .docx .pdf .json .log .xml .yaml .html`, code and other text files.

## Good to know

- **The model still sees your data.** It has to read the file in order to mask it. The skill keeps the data out of
  the chat and out of the outputs, but it doesn't hide it from the model. Follow your organization's rules on what
  data you may process with AI tools.
- **Partial masks give a little away.** Masks keep a first letter or the last 4 digits. In a small group that can
  still narrow down who someone is, so ask for full redaction when that matters.
- **You get back the format you gave.** A PDF comes back as a PDF with its layout intact: the personal details are
  removed from the file itself and their masked forms are written in the same place, in a standard font close to the
  original. Links, metadata and hidden text that hold PII are cleaned too. Excel and Word files keep their formatting.
  Scanned pages with no text layer, and photos embedded as images, can't be masked; the skill will tell you when
  that happens.
- **It's a second line of defense, not a guarantee.** Check the output before you share anything sensitive. This is
  not legal or compliance advice.
- **It isn't made by Anthropic.**

Run the tests with `python -m unittest discover -s tests`.

## License

MIT. See [LICENSE](LICENSE).
