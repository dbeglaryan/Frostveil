"""
Frostveil PDF Report Generator — pure-Python forensic report using raw PDF 1.4.

No external dependencies. Generates a valid PDF file using direct object construction
with built-in Helvetica font. Suitable for forensic documentation and court presentation.
"""
from datetime import datetime
from pathlib import Path


class PDFWriter:
    """Low-level PDF 1.4 writer that manages objects, pages, and content streams."""

    PAGE_W = 612  # Letter width in points
    PAGE_H = 792  # Letter height in points
    MARGIN_L = 60
    MARGIN_R = 60
    MARGIN_T = 60
    MARGIN_B = 60

    def __init__(self):
        self._objects = []      # list of (obj_number, bytes)
        self._pages = []        # list of page object numbers
        self._next_obj = 1
        self._current_stream = []   # text operations for current page
        self._cursor_y = self.PAGE_H - self.MARGIN_T
        self._page_started = False
        # Reserve object 1 for Catalog and 2 for Pages — we write them at save time
        self._catalog_obj = self._alloc_obj()
        self._pages_obj = self._alloc_obj()
        # Font objects (Helvetica and Helvetica-Bold)
        self._font_reg_obj = self._alloc_obj()
        self._font_bold_obj = self._alloc_obj()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _alloc_obj(self):
        num = self._next_obj
        self._next_obj += 1
        return num

    def _usable_width(self):
        return self.PAGE_W - self.MARGIN_L - self.MARGIN_R

    @staticmethod
    def _escape(text):
        """Escape special characters for PDF string literals."""
        text = str(text)
        text = text.replace("\\", "\\\\")
        text = text.replace("(", "\\(")
        text = text.replace(")", "\\)")
        # Strip non-latin1 characters since Helvetica only supports that range
        cleaned = []
        for ch in text:
            if ord(ch) < 256:
                cleaned.append(ch)
            else:
                cleaned.append("?")
        return "".join(cleaned)

    def _flush_page(self):
        """Finalize the current page's content stream and create page object."""
        if not self._page_started:
            return
        stream_text = "\n".join(self._current_stream)
        stream_bytes = stream_text.encode("latin-1", errors="replace")

        stream_obj = self._alloc_obj()
        page_obj = self._alloc_obj()

        # Content stream object
        self._objects.append((stream_obj,
            f"{stream_obj} 0 obj\n"
            f"<< /Length {len(stream_bytes)} >>\n"
            f"stream\n".encode("latin-1") + stream_bytes +
            f"\nendstream\nendobj\n".encode("latin-1")))

        # Page object
        page_def = (
            f"{page_obj} 0 obj\n"
            f"<< /Type /Page\n"
            f"   /Parent {self._pages_obj} 0 R\n"
            f"   /MediaBox [0 0 {self.PAGE_W} {self.PAGE_H}]\n"
            f"   /Contents {stream_obj} 0 R\n"
            f"   /Resources << /Font << /F1 {self._font_reg_obj} 0 R /F2 {self._font_bold_obj} 0 R >> >>\n"
            f">>\nendobj\n"
        )
        self._objects.append((page_obj, page_def.encode("latin-1")))
        self._pages.append(page_obj)

        self._current_stream = []
        self._page_started = False

    def _ensure_page(self):
        if not self._page_started:
            self.add_page()

    def _need_space(self, points):
        """Check if we need a new page; if so, break."""
        if self._cursor_y - points < self.MARGIN_B:
            self._flush_page()
            self.add_page()

    def _emit_text_line(self, text, font="F1", size=10, x=None, y=None):
        """Add a single line of text at the current or specified position."""
        if x is None:
            x = self.MARGIN_L
        if y is None:
            y = self._cursor_y
        escaped = self._escape(text)
        self._current_stream.append(
            f"BT\n/{font} {size} Tf\n{x} {y} Td\n({escaped}) Tj\nET"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_page(self):
        """Start a new blank page."""
        if self._page_started:
            self._flush_page()
        self._page_started = True
        self._cursor_y = self.PAGE_H - self.MARGIN_T
        self._current_stream = []

    def add_title(self, text):
        """Large bold title text (18pt)."""
        self._ensure_page()
        self._need_space(30)
        self._emit_text_line(text, font="F2", size=18)
        self._cursor_y -= 28

    def add_heading(self, text):
        """Section heading (13pt bold) with a separator line."""
        self._ensure_page()
        self._need_space(36)
        self._cursor_y -= 14  # extra space above heading
        # Draw a thin line
        y_line = self._cursor_y + 14
        self._current_stream.append(
            f"0.6 0.6 0.6 RG\n0.5 w\n"
            f"{self.MARGIN_L} {y_line} m {self.PAGE_W - self.MARGIN_R} {y_line} l S"
        )
        self._emit_text_line(text, font="F2", size=13)
        self._cursor_y -= 22

    def add_subheading(self, text):
        """Smaller heading (11pt bold)."""
        self._ensure_page()
        self._need_space(24)
        self._cursor_y -= 6
        self._emit_text_line(text, font="F2", size=11)
        self._cursor_y -= 18

    def add_text(self, text, indent=0):
        """Normal paragraph text (10pt). Wraps long lines manually."""
        self._ensure_page()
        lines = self._wrap_text(text, font_size=10)
        for line in lines:
            self._need_space(14)
            self._emit_text_line(line, font="F1", size=10,
                                 x=self.MARGIN_L + indent)
            self._cursor_y -= 14

    def add_key_value(self, key, value):
        """Display a label: value pair on one line."""
        self._ensure_page()
        self._need_space(16)
        escaped_key = self._escape(f"{key}:")
        escaped_val = self._escape(f"  {value}")
        self._current_stream.append(
            f"BT\n/F2 10 Tf\n{self.MARGIN_L} {self._cursor_y} Td\n"
            f"({escaped_key}) Tj\n/F1 10 Tf\n({escaped_val}) Tj\nET"
        )
        self._cursor_y -= 16

    def add_table(self, headers, rows, col_widths=None):
        """Render a simple text-aligned table."""
        self._ensure_page()
        usable = self._usable_width()
        num_cols = len(headers)

        if col_widths is None:
            col_widths = [usable / num_cols] * num_cols

        # Header row
        self._need_space(20)
        x = self.MARGIN_L
        for i, hdr in enumerate(headers):
            self._emit_text_line(str(hdr), font="F2", size=9, x=x,
                                 y=self._cursor_y)
            x += col_widths[i]
        self._cursor_y -= 4

        # Line under header
        self._current_stream.append(
            f"0.7 0.7 0.7 RG\n0.4 w\n"
            f"{self.MARGIN_L} {self._cursor_y} m "
            f"{self.PAGE_W - self.MARGIN_R} {self._cursor_y} l S"
        )
        self._cursor_y -= 14

        # Data rows
        for row in rows:
            self._need_space(14)
            x = self.MARGIN_L
            for i, cell in enumerate(row):
                cell_text = self._truncate(str(cell), col_widths[i], 8)
                self._emit_text_line(cell_text, font="F1", size=9, x=x,
                                     y=self._cursor_y)
                x += col_widths[i]
            self._cursor_y -= 14

    def add_spacer(self, points=10):
        """Add vertical whitespace."""
        self._cursor_y -= points

    def save(self, path):
        """Write the complete PDF to disk."""
        if self._page_started:
            self._flush_page()

        if not self._pages:
            self.add_page()
            self.add_text("(empty report)")
            self._flush_page()

        # Build all objects
        all_objects = []

        # Font objects
        all_objects.append((self._font_reg_obj,
            f"{self._font_reg_obj} 0 obj\n"
            f"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\n"
            f"endobj\n".encode("latin-1")))
        all_objects.append((self._font_bold_obj,
            f"{self._font_bold_obj} 0 obj\n"
            f"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\n"
            f"endobj\n".encode("latin-1")))

        # Pages object
        kids = " ".join(f"{p} 0 R" for p in self._pages)
        all_objects.append((self._pages_obj,
            f"{self._pages_obj} 0 obj\n"
            f"<< /Type /Pages /Kids [{kids}] /Count {len(self._pages)} >>\n"
            f"endobj\n".encode("latin-1")))

        # Catalog
        all_objects.append((self._catalog_obj,
            f"{self._catalog_obj} 0 obj\n"
            f"<< /Type /Catalog /Pages {self._pages_obj} 0 R >>\n"
            f"endobj\n".encode("latin-1")))

        # Page content objects
        all_objects.extend(self._objects)

        # Sort by object number
        all_objects.sort(key=lambda x: x[0])

        # Assemble PDF
        output = bytearray()
        output.extend(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

        offsets = {}
        for obj_num, data in all_objects:
            offsets[obj_num] = len(output)
            if isinstance(data, bytes):
                output.extend(data)
            else:
                output.extend(data.encode("latin-1"))

        # xref
        xref_offset = len(output)
        max_obj = max(offsets.keys())
        output.extend(f"xref\n0 {max_obj + 1}\n".encode("latin-1"))
        output.extend(b"0000000000 65535 f \n")
        for i in range(1, max_obj + 1):
            off = offsets.get(i, 0)
            output.extend(f"{off:010d} 00000 n \n".encode("latin-1"))

        # trailer
        output.extend(
            f"trailer\n<< /Size {max_obj + 1} /Root {self._catalog_obj} 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n".encode("latin-1"))

        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_bytes(bytes(output))

    # ------------------------------------------------------------------
    # Text utilities
    # ------------------------------------------------------------------

    def _wrap_text(self, text, font_size=10, max_width=None):
        """Naive word-wrap based on approximate character width."""
        if max_width is None:
            max_width = self._usable_width()
        # Approximate: Helvetica avg char width ~ 0.5 * font_size
        chars_per_line = int(max_width / (font_size * 0.5))
        if chars_per_line < 20:
            chars_per_line = 20

        words = text.replace("\r\n", "\n").replace("\r", "\n").split()
        lines = []
        current = ""
        for word in words:
            if "\n" in word:
                parts = word.split("\n")
                for j, part in enumerate(parts):
                    if j > 0:
                        lines.append(current)
                        current = ""
                    test = f"{current} {part}".strip() if current else part
                    if len(test) > chars_per_line:
                        if current:
                            lines.append(current)
                        current = part
                    else:
                        current = test
            else:
                test = f"{current} {word}" if current else word
                if len(test) > chars_per_line:
                    if current:
                        lines.append(current)
                    current = word
                else:
                    current = test
        if current:
            lines.append(current)
        return lines if lines else [""]

    @staticmethod
    def _truncate(text, col_width, font_size):
        """Truncate text to fit within a column width."""
        max_chars = int(col_width / (font_size * 0.52))
        if len(text) > max_chars:
            return text[:max_chars - 3] + "..."
        return text


# ======================================================================
# Public API
# ======================================================================

def generate(manifest, ioc_data=None, analysis_data=None, pwd_audit=None,
             output_path="frostveil_report.pdf"):
    """Generate a PDF forensic report and return the output path.

    Parameters
    ----------
    manifest : dict
        Core collection manifest with metadata, counts, total_artifacts, outputs, errors.
    ioc_data : dict, optional
        Threat intelligence / IOC report.
    analysis_data : dict, optional
        Extended analysis (privacy, domain intel, credentials, downloads, sessions).
    pwd_audit : dict, optional
        Password audit results.
    output_path : str
        Destination file path.
    """
    pdf = PDFWriter()

    meta = manifest.get("metadata", {})
    counts = manifest.get("counts", {})
    total = manifest.get("total_artifacts", sum(counts.values()))
    errors = manifest.get("errors", [])

    now_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    # ------------------------------------------------------------------
    # 1. Title Page
    # ------------------------------------------------------------------
    pdf.add_page()
    pdf.add_spacer(120)
    pdf.add_title("FROSTVEIL FORENSIC REPORT")
    pdf.add_spacer(20)
    pdf.add_text(f"Generated: {now_str}")
    pdf.add_text("Frostveil v2.0 - Browser Forensics & Penetration Testing Toolkit")
    pdf.add_spacer(30)
    pdf.add_key_value("Hostname", meta.get("hostname", "N/A"))
    pdf.add_key_value("Username", meta.get("username", "N/A"))
    pdf.add_key_value("Operating System", meta.get("os", "N/A"))
    pdf.add_key_value("Acquisition Time", meta.get("acquired_utc", "N/A"))
    pdf.add_spacer(40)
    pdf.add_text("CONFIDENTIAL - This report contains sensitive forensic data. "
                 "Handle in accordance with applicable chain-of-custody requirements.")

    # ------------------------------------------------------------------
    # 2. Executive Summary
    # ------------------------------------------------------------------
    pdf.add_page()
    pdf.add_heading("Executive Summary")

    risk_score = ioc_data.get("overall_risk_score", 0) if ioc_data else 0
    risk_level = ioc_data.get("overall_risk_level", "N/A") if ioc_data else "N/A"
    ioc_count = ioc_data.get("total_iocs", 0) if ioc_data else 0
    browsers = len([k for k in counts if k not in ("total",)])

    pdf.add_key_value("Total Artifacts Collected", f"{total:,}")
    pdf.add_key_value("Artifact Categories", str(len(counts)))
    pdf.add_key_value("Risk Level", f"{risk_level} (Score: {risk_score}/100)")
    pdf.add_key_value("IOC Indicators Detected", str(ioc_count))

    if ioc_data:
        critical_count = len(ioc_data.get("critical_findings", []))
        high_count = len(ioc_data.get("high_findings", []))
        pdf.add_key_value("Critical Findings", str(critical_count))
        pdf.add_key_value("High-Severity Findings", str(high_count))

    if analysis_data:
        cred_analysis = analysis_data.get("credential_analysis", {})
        domain_intel = analysis_data.get("domain_intel", {})
        pdf.add_key_value("Credentials Found",
                          str(cred_analysis.get("total_credentials", 0)))
        pdf.add_key_value("Unique Domains",
                          f"{domain_intel.get('unique_domains', 0):,}")

    # ------------------------------------------------------------------
    # 3. Artifact Breakdown
    # ------------------------------------------------------------------
    pdf.add_heading("Artifact Breakdown")

    if counts:
        sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)
        headers = ["Artifact Type", "Count", "Percentage"]
        rows = []
        for name, count in sorted_counts:
            pct = f"{count / max(total, 1) * 100:.1f}%"
            rows.append([name, f"{count:,}", pct])
        pdf.add_table(headers, rows, col_widths=[220, 120, 150])
    else:
        pdf.add_text("No artifact data available.")

    pdf.add_spacer(10)
    pdf.add_key_value("Total", f"{total:,}")

    # ------------------------------------------------------------------
    # 4. Threat Assessment
    # ------------------------------------------------------------------
    if ioc_data:
        pdf.add_heading("Threat Assessment")
        pdf.add_key_value("Overall Risk Score", f"{risk_score}/100")
        pdf.add_key_value("Risk Level", risk_level)
        pdf.add_key_value("URLs Scanned",
                          f"{ioc_data.get('urls_scanned', 0):,}")
        pdf.add_key_value("Total IOCs", str(ioc_count))
        pdf.add_spacer(8)

        critical_findings = ioc_data.get("critical_findings", [])
        if critical_findings:
            pdf.add_subheading("Critical Findings")
            headers = ["Type", "Severity", "URL"]
            rows = []
            for f in critical_findings[:15]:
                url = str(f.get("url", ""))
                if len(url) > 70:
                    url = url[:67] + "..."
                rows.append([
                    f.get("type", ""),
                    str(f.get("severity", "")),
                    url,
                ])
            pdf.add_table(headers, rows, col_widths=[120, 80, 290])

        high_findings = ioc_data.get("high_findings", [])
        if high_findings:
            pdf.add_spacer(8)
            pdf.add_subheading("High-Severity Findings")
            headers = ["Type", "Severity", "URL"]
            rows = []
            for f in high_findings[:10]:
                url = str(f.get("url", ""))
                if len(url) > 70:
                    url = url[:67] + "..."
                rows.append([
                    f.get("type", ""),
                    str(f.get("severity", "")),
                    url,
                ])
            pdf.add_table(headers, rows, col_widths=[120, 80, 290])

    # ------------------------------------------------------------------
    # 5. Password Audit
    # ------------------------------------------------------------------
    if pwd_audit and pwd_audit.get("total_analyzed"):
        pdf.add_heading("Password Audit")
        pdf.add_key_value("Total Passwords Analyzed",
                          str(pwd_audit["total_analyzed"]))
        pdf.add_key_value("Average Strength Score",
                          f"{pwd_audit.get('average_score', 0)}/100")
        pdf.add_key_value("Reused Passwords",
                          str(pwd_audit.get("reused_passwords", 0)))
        pdf.add_key_value("Common Passwords Found",
                          str(pwd_audit.get("common_passwords_found", 0)))
        pdf.add_spacer(8)

        dist = pwd_audit.get("strength_distribution", {})
        if dist:
            pdf.add_subheading("Strength Distribution")
            headers = ["Category", "Count", "Percentage"]
            rows = []
            for cat, cnt in sorted(dist.items(), key=lambda x: x[1],
                                   reverse=True):
                pct = f"{cnt / max(pwd_audit['total_analyzed'], 1) * 100:.1f}%"
                rows.append([cat.capitalize(), str(cnt), pct])
            pdf.add_table(headers, rows, col_widths=[180, 120, 190])

        weakest = pwd_audit.get("weakest_passwords", [])
        if weakest:
            pdf.add_spacer(8)
            pdf.add_subheading("Weakest Credentials")
            headers = ["URL", "Username", "Score", "Issues"]
            rows = []
            for w in weakest[:10]:
                url = str(w.get("url", ""))
                if len(url) > 40:
                    url = url[:37] + "..."
                issues = ", ".join(w.get("issues", []))
                if len(issues) > 35:
                    issues = issues[:32] + "..."
                rows.append([
                    url,
                    str(w.get("username", "")),
                    str(w.get("score", "")),
                    issues,
                ])
            pdf.add_table(headers, rows,
                          col_widths=[160, 100, 50, 180])

    # ------------------------------------------------------------------
    # 6. Timeline Summary
    # ------------------------------------------------------------------
    pdf.add_heading("Timeline Summary")

    if analysis_data and analysis_data.get("session_reconstruction"):
        sessions = analysis_data["session_reconstruction"]
        pdf.add_key_value("Total Sessions", str(sessions.get("total_sessions", 0)))
        if sessions.get("date_range"):
            dr = sessions["date_range"]
            pdf.add_key_value("Earliest Activity", str(dr.get("start", "N/A")))
            pdf.add_key_value("Latest Activity", str(dr.get("end", "N/A")))
    else:
        pdf.add_text("Detailed timeline data not available for this collection.")

    pdf.add_key_value("Collection Timestamp", meta.get("acquired_utc", "N/A"))
    pdf.add_key_value("Total Artifacts in Scope", f"{total:,}")

    # ------------------------------------------------------------------
    # Output Files
    # ------------------------------------------------------------------
    outputs = manifest.get("outputs", {})
    if outputs:
        pdf.add_heading("Output Files")
        headers = ["Filename", "SHA-256 Hash"]
        rows = []
        for fname, sha in outputs.items():
            rows.append([str(fname), str(sha)])
        pdf.add_table(headers, rows, col_widths=[200, 290])

    # ------------------------------------------------------------------
    # Errors
    # ------------------------------------------------------------------
    if errors:
        pdf.add_heading(f"Errors ({len(errors)})")
        for err in errors[:20]:
            pdf.add_text(str(err), indent=10)

    # ------------------------------------------------------------------
    # Footer / Disclaimer
    # ------------------------------------------------------------------
    pdf.add_heading("Disclaimer")
    pdf.add_text(
        "This report was generated automatically by Frostveil v2.0. All data "
        "was collected from browser artifacts on the target system. The findings "
        "herein are based on automated analysis and should be reviewed by a "
        "qualified forensic examiner before being used as evidence. Chain-of-custody "
        "documentation should accompany this report."
    )
    pdf.add_spacer(20)
    pdf.add_text(f"End of report. Generated {now_str}.")

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------
    pdf.save(output_path)
    return output_path
