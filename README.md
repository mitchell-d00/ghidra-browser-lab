# Ghidra Browser Lab

A **browser-based, MPLPB-style reverse-engineering workbench** inspired by Ghidra, with the same delivery shape as your uploaded MPLPB project: a root `index.html`, a single-file HTML export, an optional Python localhost launcher, and a bridge to the **original tool** where possible.

**Important:** This does **not** convert the NSA's Java Ghidra desktop application to JavaScript or run the JVM in HTML. The browser can inspect binary bytes, decode a limited subset of x86 instructions, patch and export bytes, and solve four built-in challenges. For **real Ghidra decompilation**, a local Python server invokes an actual installed Ghidra `analyzeHeadless` Java process and displays its output. It never runs a binary being inspected.

## Launch / play now

- **No installs:** Open `Ghidra_Browser_Lab.html` in any modern browser. Everything in browser mode works offline. Double-click it; no Python or server required. Or deploy the root `index.html` plus its `app.js`, `analyzer.js`, and `style.css` on GitHub Pages.
- **Windows local server:** Double-click `Launch_Browser_Lab.bat`.
- **Mac/Linux local server:** Run `sh Launch_Browser_Lab.sh`.
- **From terminal:** `python3 launch.py`. Browse to `http://127.0.0.1:8767`.

The launcher works without Ghidra and serves the same gameplay; actual Ghidra engine connectivity stays disabled until configured.

## Optional: connect real Ghidra

1. Download the official Ghidra release from https://github.com/NationalSecurityAgency/ghidra/releases and follow its current JDK installation requirements (the inspected master README specifies **JDK 25**).
2. Extract Ghidra. Make sure the directory contains `support/analyzeHeadless` (or `support/analyzeHeadless.bat` on Windows).
3. Run `python3 launch.py --ghidra-home /absolute/path/to/ghidra` or set `GHIDRA_HOME` and run the normal launcher. Windows: `py -3 launch.py --ghidra-home "C:\\path\\to\\ghidra"`.
4. In the browser, open an **ELF, PE, or Mach-O** executable and click **Analyze with real Ghidra**. Pick a function from the new selector; inspect real instruction listing and pseudocode. The user interface marks genuine results separately from the browser decoder.

The Java exporter source is `bridge/WebExport.java`. It is executed by Ghidra as a Java GhidraScript after Ghidra's normal headless analysis. **The full Ghidra desktop experience (debugger, graphs, plugins, bulk analysis, and project editing) is not available in this app.** Real Ghidra is an optional local dependency, not shipped in this archive.

## Interactive challenges

| Mission | Goal | Feature |
| --- | --- | --- |
| The Vault | Find the input for the simple access check | Disassembly / compares |
| Signal Gate | Decode a 32-bit comparison constant | Little-endian immediates |
| Branch Flip | Patch jump opcode at offset `0x03` from `75` to `74` | Hex editor |
| Hidden Marker | Find the `MAINT_KEY` value | Strings |

Solved levels and theme are saved in browser local storage. Uploaded binary content and analysis results are not saved in local storage. You can export a modified binary. This is a **learning workbench**, not a complete disassembler. Unsupported opcodes render as `db`; heuristic pseudocode is never labeled as real Ghidra.

## Publish (GitHub Pages)

A workflow is provided at `.github/workflows/pages.yml`. Push this folder to a GitHub repo, open **Settings → Pages**, select **GitHub Actions** as the source and run the workflow. Only the four public static files are deployed. This supports the four game missions and browser inspection. **GitHub Pages cannot host a Java Ghidra server or run `analyzeHeadless`.** Real analysis requires the localhost bridge (or a separately designed secure backend).

## Security and privacy

- By default browser mode handles chosen files entirely in your device's browser; no uploads or external requests are required, except an innocuous status request when served via HTTP.
- The server binds **only** to `127.0.0.1`, checks cross-origin API requests, accepts at most 8 MiB, and uses disposable project folders. Do not expose this development bridge to the internet.
- Ghidra parses untrusted executable formats. Do not analyze suspected malware outside a disposable virtual machine and do not use a sensitive workstation for that job. Review Ghidra security advisories.
- The tool never launches, executes, or emulates the uploaded binary. The patch feature edits bytes and exports a copy only.

## Implementation / verification

- `analyzer.js`: actual byte and header parsing, string scanner, limited decoder, hexdump and mission validator.
- `app.js`: responsive browser UI, state, patches, score and local bridge connectivity.
- `style.css` + `index.html`: MPLPB-like explorer, workbench, inspector and journal layout.
- `launch.py`: small Python 3 standard-library localhost server and Ghidra process wrapper.
- `bridge/WebExport.java`: Ghidra Java post-script, exports up to 50 functions and 120 instructions per function to structured JSON.
- `tests/`: Node and Python offline checks. Run `node tests/browser.test.js` and `python3 -m unittest discover -s tests`.
- `tools/build_standalone.py`: rebuild the offline single HTML distribution.

### License and provenance

The Ghidra project is produced by the US National Security Agency and released under Apache-2.0. This lab is a new front end; it **does not distribute Ghidra source or binaries, or claim to be an official NSA/Ghidra UI**. It is compatible with connecting an independently installed official release. The delivered lab source is under the MIT license in this project.