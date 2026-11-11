# Manual source and offline build

The shareable [GhidraMSC User Manual PDF](GhidraMSC_User_Manual.pdf) is built
from [USER_MANUAL.md](USER_MANUAL.md) and the five cropped PNG files in
`images/`. `make_demo_elf.py` generates the disposable analysis target used in
the walkthrough. The PDF embeds its screenshots and does not need this source
directory when opened elsewhere.

The source format is Markdown. A three-page layout sample with contents,
commands, screenshot, caption, and internal link was built and visually
inspected before the full manual. `build_pdf.py` is a small, deterministic,
offline renderer for the Markdown constructs used in this manual; it is not a
general Markdown converter.

## Rebuild without network access

From the GhidraMSC root, use a Python environment with ReportLab and Pillow
already installed. The accepted build used ReportLab 4.4.9 and Pillow 12.3.0.
The builder reads only the local Markdown and PNG files; it does not fetch
resources or modify Ghidra projects.

```powershell
python -c "import reportlab, PIL; print(reportlab.Version, PIL.__version__)"
python docs/user-manual/build_pdf.py
```

Expected output is `docs/user-manual/GhidraMSC_User_Manual.pdf`. The builder
accepts `--source` and `--output` for an alternate local source or destination.
After editing, render and inspect every page, and check the table of contents,
internal links, screenshots, page numbers, and copyable commands.

## Screenshot provenance

The five PNGs were cropped from a live Ghidra 12.1.4 session using the
disposable `ManualDemo_1214` project and its `demo_add_one.elf` program. The
project tree, CodeBrowser listing, decompiler, checked plugin entry, and saved
plate-comment view correspond to Figures 1-5 in the manual. No personal or
production program is shown.
