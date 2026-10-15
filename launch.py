#!/usr/bin/env python3
"""Serve the browser workbench and optional local-only Ghidra headless analysis.

No third-party Python packages required. Does not execute inspected binaries.
"""
import argparse
import json
import os
from pathlib import Path
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import subprocess
import tempfile
import urllib.parse
import webbrowser

ROOT = Path(__file__).resolve().parent
MAX_BYTES = 8 * 1024 * 1024


def find_ghidra(path=None):
    """Return absolute headless executable only when a valid install is found."""
    val = path or os.environ.get("GHIDRA_HOME")
    if not val:
        return None
    home = Path(val).expanduser().resolve()
    names = ["analyzeHeadless.bat", "analyzeHeadless"] if os.name == "nt" else ["analyzeHeadless", "analyzeHeadless.bat"]
    for filename in names:
        script = home / "support" / filename
        if script.is_file():
            return script
    return None


def is_executable(data):
    if data.startswith(b"\x7fELF") or data.startswith(b"MZ"):
        return True
    return data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


def analyze(data, filename, analyzer, seconds=130):
    """Import one executable into a disposable Ghidra project and export up to 50 funcs."""
    if not is_executable(data):
        raise ValueError("Real Ghidra mode expects a recognized executable (PE, ELF or Mach-O). For raw bytes use Browser Mode.")
    suffix = Path(filename).suffix.lower()
    if suffix not in ('.exe', '.dll', '.elf', '.so', '.o', '.out', '.bin', '.dylib', '.mach'):
        suffix = '.bin'
    with tempfile.TemporaryDirectory(prefix='ghidra-browser-') as tmp:
        work = Path(tmp)
        infile = work / ('sample' + suffix)
        outfile = work / 'result.json'
        infile.write_bytes(data)
        project = work / 'projects'
        project.mkdir()
        cmd = [str(analyzer), str(project), 'BrowserLab', '-import', str(infile),
               '-analysisTimeoutPerFile', '65', '-postScript', 'WebExport.java', str(outfile),
               '-scriptPath', str(ROOT / 'bridge'), '-max-cpu', '2', '-deleteProject']
        proc = subprocess.run(cmd, cwd=str(work), capture_output=True, text=True,
                              timeout=seconds, check=False, errors='replace')
        if not outfile.is_file():
            tail = ('\n'.join((proc.stdout + '\n' + proc.stderr).splitlines()[-12:]))[-1400:]
            raise RuntimeError('Ghidra could not analyze this file. Check that your Ghidra and JDK versions match.\n' + tail)
        if outfile.stat().st_size > 9 * 1024 * 1024:
            raise RuntimeError('Ghidra analysis output exceeded the safe response size.')
        return json.loads(outfile.read_text(encoding='utf-8'))


class Handler(SimpleHTTPRequestHandler):
    ghidra_cmd = None
    server_port = 8767

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def _json(self, status, data):
        buf = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(buf)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(buf)

    def do_GET(self):
        if urllib.parse.urlsplit(self.path).path == '/api/status':
            self._json(200, {'available': self.ghidra_cmd is not None,
                             'mode': 'localhost',
                             'message': 'Ghidra detected' if self.ghidra_cmd else 'Run with --ghidra-home PATH or set GHIDRA_HOME'})
            return
        super().do_GET()

    def do_POST(self):
        if urllib.parse.urlsplit(self.path).path != '/api/analyze':
            self._json(404, {'error': 'API endpoint not found'})
            return
        origin = self.headers.get('Origin', '')
        if origin and origin not in ('http://127.0.0.1:' + str(self.server_port), 'http://localhost:' + str(self.server_port)):
            self._json(403, {'error': 'Cross-origin calls to the local bridge are blocked'})
            return
        if self.ghidra_cmd is None:
            self._json(503, {'error': 'Ghidra installation not configured. Restart launcher with --ghidra-home.'})
            return
        try:
            length = int(self.headers.get('Content-Length', '-1'))
        except ValueError:
            length = -1
        if not 0 < length <= MAX_BYTES:
            self._json(413, {'error': 'Binary must be between 1 byte and 8 MiB'})
            return
        data = self.rfile.read(length)
        if len(data) != length:
            self._json(400, {'error': 'Incomplete upload'})
            return
        name = urllib.parse.unquote(self.headers.get('X-Filename', 'sample.bin'))[:130]
        try:
            out = analyze(data, name, self.ghidra_cmd)
            self._json(200, out)
        except subprocess.TimeoutExpired:
            self._json(504, {'error': 'Ghidra analysis exceeded its configured time limit'})
        except (ValueError, RuntimeError) as exc:
            self._json(422, {'error': str(exc)[:1600]})
        except Exception as exc:
            self._json(500, {'error': 'Analysis failed (' + type(exc).__name__ + '). Inspect the local server terminal.'})

    def log_message(self, fmt, *args):
        print('%s - %s' % (self.address_string(), fmt % args))


def main():
    parser = argparse.ArgumentParser(description='Ghidra Browser Lab localhost launcher')
    parser.add_argument('--port', type=int, default=8767)
    parser.add_argument('--ghidra-home', help='Path to official extracted Ghidra directory')
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    Handler.ghidra_cmd = find_ghidra(args.ghidra_home)
    Handler.server_port = args.port
    url = f'http://127.0.0.1:{args.port}/'
    print(f'Browser Lab at {url}')
    if Handler.ghidra_cmd:
        print(f'Real Ghidra integration: enabled ({Handler.ghidra_cmd})')
    else:
        print('Real Ghidra integration: not configured; browser-only mode still works.')
    with ThreadingHTTPServer(('127.0.0.1', args.port), Handler) as server:
        if not args.no_browser:
            import threading
            threading.Timer(0.35, lambda: webbrowser.open(url)).start()
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print('\nStopped.')

if __name__ == '__main__':
    main()
