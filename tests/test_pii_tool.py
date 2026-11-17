"""Tests for the /pii-mask skill. All data below is made up."""
import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
SKILL_DIR = os.path.join(ROOT, "skills", "pii-mask")
SCRIPT = os.path.join(SKILL_DIR, "scripts", "pii_tool.py")
sys.path.insert(0, os.path.join(SKILL_DIR, "scripts"))
import pii_tool  # noqa: E402

SAMPLE = (
    "Contact Ravi Kumar at +91 98765 43210 or ravi.kumar@example.com.\n"
    "Aadhaar: 2345 6789 0123, PAN ABCDE1234F, card 4111 1111 1111 1111.\n"
    "SSN 123-45-6789, server 192.168.10.44. DOB: 12/03/1995. Passport No: K1234567.\n"
    "Profile https://www.linkedin.com/in/ravikumar99 ; UPI ravi99@okaxis ; write to support@shop.example.in\n"
    "Invoice total 125000, order 2024-11-05, version 3.2.1, qty 12.\n"
)
RAW_VALUES = ["98765 43210", "ravi.kumar@", "2345 6789 0123", "ABCDE1234F", "4111 1111 1111 1111",
              "123-45-6789", "192.168.10.44", "12/03/1995", "K1234567", "ravikumar99", "ravi99@", "Ravi", "Kumar"]


class SkillFileTest(unittest.TestCase):
    def setUp(self):
        with open(os.path.join(SKILL_DIR, "SKILL.md"), encoding="utf-8") as f:
            self.text = f.read()

    def test_frontmatter(self):
        self.assertTrue(self.text.startswith("---\nname: pii-mask\n"))
        head = self.text.split("---")[1]
        for key in ("description:", "argument-hint:", "license: MIT"):
            self.assertIn(key, head)

    def test_three_agents_and_rules(self):
        for part in ("### 1. Masker", "### 2. Tester", "### 3. Auditor", "## Privacy rules",
                     "Never create a key or mapping file", "**only the masked file**"):
            self.assertIn(part, self.text)


class MaskTest(unittest.TestCase):
    def run_mask(self, name, content, terms=""):
        d = tempfile.mkdtemp()
        run = os.path.join(d, ".pii-masked", "run")
        src, out, tf = os.path.join(d, name), os.path.join(run, name), os.path.join(d, "terms.tsv")
        with open(src, "w", encoding="utf-8", newline="") as f:
            f.write(content)
        with open(tf, "w", encoding="utf-8") as f:
            f.write(terms)
        with redirect_stdout(io.StringIO()):
            pii_tool.cmd_mask(src, out, tf)
        with open(out, encoding="utf-8", newline="") as f:
            return f.read(), out

    def test_masks_every_pattern(self):
        out, _ = self.run_mask("t.txt", SAMPLE, "NAME\tRavi Kumar\nNAME\tRavi\nNAME\tKumar\n")
        for raw in RAW_VALUES:
            self.assertNotIn(raw, out, raw)
        for kept in ("125000", "2024-11-05", "3.2.1", "qty 12", "support@shop.example.in"):
            self.assertIn(kept, out)
        for masked in ("+91 98******10", "r***@example.com", "**** **** 0123", "**** **** **** 1111",
                       "***-**-6789", "192.168.*.*", "**/**/1995", "R*** K****"):
            self.assertIn(masked, out)

    def test_masked_output_scans_clean(self):
        _, path = self.run_mask("t.txt", SAMPLE, "NAME\tRavi Kumar\nNAME\tRavi\nNAME\tKumar\n")
        with redirect_stdout(io.StringIO()):
            self.assertEqual(pii_tool.cmd_scan(path), 0)

    def test_csv_columns_and_line_endings(self):
        csv_in = "id,Customer Name,Mobile,Fee\r\n1,Anita Desai,9812345678,499\r\n"
        out, _ = self.run_mask("c.csv", csv_in)
        self.assertIn("\r\n", out)
        self.assertNotIn("Anita", out)
        self.assertNotIn("9812345678", out)
        self.assertIn("499", out)

    def test_scan_never_prints_raw_values(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "s.txt")
        with open(p, "w", encoding="utf-8") as f:
            f.write(SAMPLE)
        r = subprocess.run([sys.executable, "-I", SCRIPT, "scan", p], capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(r.returncode, 1)
        for raw in RAW_VALUES[:11]:
            self.assertNotIn(raw, r.stdout, raw)

    def test_writes_only_inside_pii_masked(self):
        d = tempfile.mkdtemp()
        src = os.path.join(d, "a.txt")
        with open(src, "w", encoding="utf-8") as f:
            f.write(SAMPLE)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(pii_tool.cmd_mask(src, os.path.join(d, "elsewhere.txt"), None), 2)
            self.assertEqual(pii_tool.cmd_text(src, os.path.join(d, "dump.txt")), 2)
            self.assertEqual(pii_tool.cmd_clean(d), 2)
        self.assertFalse(os.path.exists(os.path.join(d, "elsewhere.txt")))

    def test_compare_and_clean(self):
        out, path = self.run_mask("t.txt", SAMPLE)
        run = os.path.dirname(path)
        work = os.path.join(run, ".work")
        os.makedirs(work)
        buf = io.StringIO()
        with redirect_stdout(buf):
            pii_tool.cmd_compare(os.path.join(os.path.dirname(os.path.dirname(run)), "t.txt"), path)
            pii_tool.cmd_clean(run)
        report = buf.getvalue()
        self.assertIn("original=5 masked=5", report)
        for raw in RAW_VALUES[:11]:
            self.assertNotIn(raw, report)
        self.assertFalse(os.path.exists(work))

    def test_output_keeps_input_format(self):
        d = tempfile.mkdtemp()
        src = os.path.join(d, "a.txt")
        with open(src, "w", encoding="utf-8") as f:
            f.write(SAMPLE)
        with redirect_stdout(io.StringIO()):
            rc = pii_tool.cmd_mask(src, os.path.join(d, ".pii-masked", "run", "a.masked.md"), None)
        self.assertEqual(rc, 2)

    def test_letter_spaced_names(self):
        self.assertEqual(pii_tool.mask_name("J O H N D O E"), "J * * * * * *")
        self.assertEqual(pii_tool.mask_name("John Doe"), "J*** D**")

    def test_dob_in_a_sentence_with_two_digit_year(self):
        out, _ = self.run_mask("t.txt", "Hi, my DOB is 07-21-88 and I was born on 21.07.1988. Order 07-21-88-X.\n")
        self.assertNotIn("07-21-88 ", out)
        self.assertIn("**-**-88", out)
        self.assertIn("**.**.1988", out)

    def test_dates_keep_the_year(self):
        self.assertEqual(pii_tool.mask_date("1988-07-21 00:00:00"), "**/**/1988")
        self.assertEqual(pii_tool.mask_date("21/07/1988"), "**/**/1988")
        self.assertEqual(pii_tool.mask_date("07-21-88"), "**-**-88")

    def test_ids_keep_last_chars_and_shape(self):
        self.assertEqual(pii_tool.mask_last4("ABCDE1234F"), "******234F")
        self.assertEqual(pii_tool.mask_last4("D123-4567-8901"), "****-****-8901")
        self.assertEqual(pii_tool.mask_last4("1234567"), "*****67")   # short ID: never show half
        self.assertEqual(pii_tool.mask_last4("1234"), "****")

    def test_header_types(self):
        cases = {
            "Person Name": "NAME", "customerName": "NAME", "first_name": "NAME", "Name": "NAME",
            "Applicant Name": "NAME", "Account Holder": "NAME",
            "Company Name": None, "Product Name": None, "Street Name": "ADDRESS", "File name": None,
            "Drivers License": "ID", "License Number": "ID", "License Issue Date": None, "Licence Class": None,
            "SSN": "ID", "Passport No": "ID", "Account Number": "ID", "Account Type": None,
            "Zip Code": "ZIP", "Postal Code": "ZIP", "PIN code": "ZIP",
            "DOB": "DOB", "Date of Birth": "DOB", "Place of Birth": None,
            "Street": "ADDRESS", "Shipping Address": "ADDRESS", "Email Address": None, "IP Address": None,
            "State": None, "City": None, "Purchase Date": None, "Amount": None, "transactionID": None,
        }
        for header, want in cases.items():
            self.assertEqual(pii_tool.header_type(header), want, header)

    def test_luhn_rejects_random_numbers(self):
        self.assertTrue(pii_tool._luhn("4111111111111111"))
        self.assertFalse(pii_tool._luhn("4111111111111112"))


try:
    import openpyxl
except ImportError:
    openpyxl = None


@unittest.skipIf(openpyxl is None, "openpyxl not installed")
class XlsxTest(unittest.TestCase):
    """A US-style table: every PII column is masked from its header alone, with no terms file."""

    def test_columns_masked_from_headers(self):
        import datetime
        d = tempfile.mkdtemp()
        src = os.path.join(d, "people.xlsx")
        out = os.path.join(d, ".pii-masked", "run", "people.masked.xlsx")
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.append(["Person Name", "State", "Drivers License", "Issue Date", "SSN", "transactionID",
                   "Street", "City", "Zip Code", "DOB", "Amount", "Total"])
        ws.append(["Jordan Avery", "Ohio", "TQ482915", datetime.datetime(2020, 3, 1), "321-54-9876",
                   "321-54-9876", "77 Birch Lane", "Columbus", 43004, datetime.datetime(1984, 9, 30), 120, None])
        ws.append(["Casey Moreno", "Maine", "A2210-3304", datetime.datetime(2019, 6, 2), "210-98-7654",
                   "TX-1001", "5 Elm Court", "Portland", 4101, datetime.datetime(1990, 1, 5), 80, None])
        ws["L2"] = "=K2*2"
        wb.save(src)
        with redirect_stdout(io.StringIO()):
            self.assertEqual(pii_tool.cmd_mask(src, out, None), 0)
            self.assertEqual(pii_tool.cmd_scan(out), 0)
        rows = list(openpyxl.load_workbook(out).active.iter_rows(values_only=True))
        flat = " ".join(str(v) for r in rows for v in r)
        for raw in ("Jordan", "Avery", "Casey", "TQ482915", "A2210-3304", "321-54-9876", "Birch", "43004",
                    "1984-09-30"):
            self.assertNotIn(raw, flat, raw)
        self.assertEqual(rows[1][0], "J***** A****")
        self.assertEqual(rows[1][2], "****2915")
        self.assertEqual(rows[2][2], "*****-3304")
        self.assertEqual(rows[1][4], "***-**-9876")
        self.assertEqual(rows[1][5], "***-**-9876")
        self.assertEqual(rows[1][8], "*****")
        self.assertEqual(rows[1][9], "**/**/1984")
        for kept in ("Ohio", "Columbus", "TX-1001", "2020-03-01", "120", "=K2*2"):
            self.assertIn(kept, flat, kept)
        buf = io.StringIO()
        with redirect_stdout(buf):
            pii_tool.cmd_compare(src, out)
        report = buf.getvalue()
        self.assertIn("Changed by column", report)
        self.assertNotIn("Jordan", report)


try:
    import pymupdf
except ImportError:
    pymupdf = None


@unittest.skipIf(pymupdf is None, "PyMuPDF not installed")
class PdfTest(unittest.TestCase):
    """A PDF comes back as a PDF, with the layout kept and the PII gone from the file itself."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.src = os.path.join(self.d, "cv.pdf")
        self.out = os.path.join(self.d, ".pii-masked", "run", "cv.masked.pdf")
        doc = pymupdf.open()
        p = doc.new_page()
        p.draw_rect(pymupdf.Rect(40, 30, 560, 80), color=None, fill=(0.85, 0.9, 1))
        p.insert_text((50, 60), "Ravi Kumar", fontsize=20, fontname="hebo")
        p.insert_text((50, 100), "Email: ravi.kumar@example.com  |  Phone: +91 98765 43210", fontsize=10)
        p.insert_text((50, 115), "linkedin.com/in/ravikumar99", fontsize=10)
        p.insert_link({"kind": pymupdf.LINK_URI, "from": pymupdf.Rect(300, 300, 400, 320),
                       "uri": "mailto:ravi.kumar@example.com"})
        p.insert_text((50, 140), "Summary: Ravi led a team at Acme Corp, revenue up 25% in 2023.",
                      fontsize=10, fontname="tiro")
        p.insert_text((350, 160), "Invoice total 125000", fontsize=10)
        doc.set_metadata({"author": "Ravi Kumar", "title": "CV"})
        doc.save(self.src)
        tf = os.path.join(self.d, "terms.tsv")
        with open(tf, "w", encoding="utf-8") as f:
            f.write("NAME\tRavi Kumar\nNAME\tRavi\n")
        with redirect_stdout(io.StringIO()):
            self.rc = pii_tool.cmd_mask(self.src, self.out, tf)

    def test_pdf_in_pdf_out(self):
        self.assertEqual(self.rc, 0)
        with open(self.out, "rb") as f:
            self.assertTrue(f.read(5).startswith(b"%PDF"))
        with redirect_stdout(io.StringIO()):
            self.assertEqual(pii_tool.cmd_scan(self.out), 0)

    def test_pii_gone_from_text_links_and_metadata(self):
        doc = pymupdf.open(self.out)
        text = "".join(p.get_text() for p in doc)
        for raw in ("Ravi", "Kumar", "ravi.kumar@", "98765 43210", "ravikumar99"):
            self.assertNotIn(raw, text, raw)
        for kept in ("Acme Corp", "25% in 2023", "Invoice total 125000"):
            self.assertIn(kept, text)
        for masked in ("R*** K****", "r***@example.com", "+91 98******10"):
            self.assertIn(masked, text)
        self.assertEqual([lk for p in doc for lk in p.get_links()], [])
        self.assertNotIn("Ravi", doc.metadata["author"])

    def test_layout_kept(self):
        before, after = pymupdf.open(self.src)[0], pymupdf.open(self.out)[0]
        # Text that follows a masked value on the same line must not slide.
        tails = [(c, x, y) for c, x, y in pii_tool._kept_chars(pii_tool._pdf_lines(before), [])
                 if (abs(y - 140) < 1 and x > 115) or (abs(y - 100) < 1 and 195 < x < 245)]   # "|  Phone:"
        self.assertTrue(tails)
        self.assertEqual(pii_tool._misplaced(after, tails), [])
        self.assertEqual(len(before.get_drawings()), len(after.get_drawings()))


if __name__ == "__main__":
    unittest.main()
