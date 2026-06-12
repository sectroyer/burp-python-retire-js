# -*- coding: utf-8 -*-
"""
Retire.js passive scanner for Burp Suite.
Identifies vulnerable JavaScript libraries using the Retire.js vulnerability database.

Ported from the Java extension by h3xstream:
  https://github.com/h3xstream/burp-retire-js

Retire.js database:
  https://github.com/RetireJS/retire.js
"""

from burp import IBurpExtender, IScannerCheck, IScanIssue, IProxyListener

import hashlib
import json
import os
import re
import sys

try:
    from urllib2 import urlopen
except ImportError:
    from urllib.request import urlopen

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPO_URL = (
    "https://raw.githubusercontent.com/Retirejs/retire.js"
    "/master/repository/jsrepository.json"
)
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".retirejs")
CACHE_FILE = os.path.join(CACHE_DIR, "jsrepository.json")

# Jython inside Burp does not set __file__; search sys.path for the DB instead.
try:
    _SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
except NameError:
    _SCRIPT_DIR = next(
        (p for p in sys.path if os.path.exists(os.path.join(p, "jsrepository.json"))),
        os.getcwd(),
    )
BUNDLED_DB = os.path.join(_SCRIPT_DIR, "jsrepository.json")
CUSTOM_DB  = os.path.join(_SCRIPT_DIR, "custom_repository.json")

HTML_EXTENSIONS = ('.html', '.htm', '.aspx', '.asp', '.php', '.jsp', '.jspx')

# Matches <script ... src="..."> or <script ... src='...'>
_SCRIPT_SRC_RE = re.compile(
    r'<[sS][cC][rR][iI][pP][tT][^>]*[sS][rR][cC]=["\']([^"\']*)["\']'
)

# Version placeholder used in the retire.js pattern database (§§version§§)
_VERSION_PLACEHOLDER = u'§§version§§'
_VERSION_REGEX = '[0-9][0-9.a-z_-]+'

# ---------------------------------------------------------------------------
# Pattern helpers
# ---------------------------------------------------------------------------

def _replace_version(pattern):
    """Expand §§version§§ placeholder to a version-matching regex fragment."""
    pattern = pattern.replace(_VERSION_PLACEHOLDER, _VERSION_REGEX)
    # Also handle ##version## (alternative placeholder used in some DB versions)
    pattern = pattern.replace('##version##', _VERSION_REGEX)
    if '{}' in pattern:
        pattern = pattern.replace('{}', '\\{\\}')
    if '\n' in pattern:
        pattern = pattern.replace('\n', '\\n')
    if '[]' in pattern:
        pattern = pattern.replace('[]', '\\[\\]')
    return pattern


def _simple_match(pattern, data):
    """Return the first capture group of `pattern` matched against `data`, or None."""
    try:
        m = re.search(pattern, data)
        if m and m.lastindex and m.lastindex >= 1:
            return m.group(1)
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Version comparison  (mirrors CompareVersionUtil.java)
# ---------------------------------------------------------------------------

def _split_version(v):
    return [_part_int(p) for p in re.split(r'[.\-]', v)]


def _part_int(s):
    if s == '*':
        return None  # wildcard – always skipped in comparisons
    try:
        return int(s)
    except (ValueError, TypeError):
        return 0


def _is_under(version, under):
    """Return True if version < under (mirrors CompareVersionUtil.isUnder)."""
    v1 = _split_version(version)
    v2 = _split_version(under)
    for i in range(max(len(v1), len(v2))):
        b = v2[i] if i < len(v2) else 0
        if b is None:
            continue  # wildcard
        a = v1[i] if i < len(v1) else 0
        if a is None:
            a = 0
        if a > b:
            return False
        if a < b:
            return True
    return False  # equal


def _at_or_above(version, ref):
    """Return True if version >= ref (mirrors CompareVersionUtil.atOrAbove)."""
    v1 = _split_version(version)
    v2 = _split_version(ref)
    for i in range(max(len(v1), len(v2))):
        b = v2[i] if i < len(v2) else 0
        if b is None:
            continue  # wildcard
        a = v1[i] if i < len(v1) else 0
        if a is None:
            a = 0
        if a < b:
            return False
        if a > b:
            return True
    return True  # equal


# ---------------------------------------------------------------------------
# Domain objects
# ---------------------------------------------------------------------------

class JsVulnerability(object):
    def __init__(self, at_or_above, below, info, identifiers, severity):
        self.at_or_above = at_or_above
        self.below = below
        self.info = info or []
        self.identifiers = identifiers or {}
        self.severity = severity or 'medium'


class JsLibrary(object):
    def __init__(self, name):
        self.name = name
        self.vulnerabilities = []
        self.uris = []
        self.filename = []
        self.file_contents = []
        self.hashes = {}
        self.functions = []
        self.headers = []


class JsLibraryResult(object):
    def __init__(self, library, vuln, version, regex_request=None, regex_response=None, via_header=False):
        self.library = library
        self.vuln = vuln
        self.version = version
        self.regex_request = regex_request
        self.regex_response = regex_response
        self.via_header = via_header


# ---------------------------------------------------------------------------
# Vulnerability database
# ---------------------------------------------------------------------------

class VulnerabilitiesRepository(object):
    def __init__(self):
        self.libraries = []

    def find_by_uri(self, uri):
        results = []
        for lib in self.libraries:
            for pattern in lib.uris:
                version = _simple_match(pattern, uri)
                if version is not None:
                    self._collect_vulnerable(lib, version, results, pattern, None)
                    break
        return results

    def find_by_filename(self, filename):
        results = []
        for lib in self.libraries:
            for pattern in lib.filename:
                version = _simple_match(pattern, filename)
                if version is not None:
                    self._collect_vulnerable(lib, version, results, pattern, None)
                    break
        return results

    def find_by_hash(self, file_hash):
        for lib in self.libraries:
            version = lib.hashes.get(file_hash)
            if version is not None:
                results = []
                self._collect_vulnerable(lib, version, results, None, None)
                return results
        return []

    def find_by_file_content(self, content):
        results = []
        for lib in self.libraries:
            for pattern in lib.file_contents:
                try:
                    version = _simple_match(pattern, content)
                except Exception:
                    version = None
                if version is not None:
                    self._collect_vulnerable(lib, version, results, None, pattern)
                    break
        return results

    def find_by_headers(self, headers):
        results = []
        for lib in self.libraries:
            for pattern in lib.headers:
                for header in headers:
                    version = _simple_match(pattern, header)
                    if version is not None:
                        self._collect_vulnerable(lib, version, results, pattern, None, via_header=True)
                        break
                else:
                    continue
                break
        return results

    def _collect_vulnerable(self, lib, version, results, regex_req, regex_resp, via_header=False):
        for vuln in lib.vulnerabilities:
            if not vuln.below:
                continue
            if _is_under(version, vuln.below):
                if vuln.at_or_above is None or _at_or_above(version, vuln.at_or_above):
                    results.append(JsLibraryResult(lib, vuln, version, regex_req, regex_resp, via_header=via_header))


class DatabaseLoader(object):
    def load(self, log=None):
        def _log(msg):
            if log:
                try:
                    log(msg)
                except Exception:
                    pass

        # 1. Try downloading the latest database from the remote repository
        main_repo = None
        try:
            if not os.path.exists(CACHE_DIR):
                os.makedirs(CACHE_DIR)
            _log("Downloading latest Retire.js database...")
            response = urlopen(REPO_URL, timeout=15)
            data = response.read()
            with open(CACHE_FILE, 'wb') as f:
                f.write(data)
            _log("Retire.js database updated from remote.")
            main_repo = self._parse(data)
        except Exception as e:
            _log("Could not download Retire.js database: {}".format(str(e)))

        # 2. Fall back to the locally cached copy
        if main_repo is None and os.path.exists(CACHE_FILE):
            _log("Loading cached Retire.js database.")
            try:
                with open(CACHE_FILE, 'rb') as f:
                    main_repo = self._parse(f.read())
            except Exception as e:
                _log("Could not read cache: {}".format(str(e)))

        # 3. Fall back to the bundled database shipped with the extension
        if main_repo is None and os.path.exists(BUNDLED_DB):
            _log("Loading bundled Retire.js database.")
            with open(BUNDLED_DB, 'rb') as f:
                main_repo = self._parse(f.read())

        if main_repo is None:
            raise RuntimeError(
                "Retire.js: could not load vulnerability database from "
                "remote, cache, or bundled copy."
            )

        # 4. Load and merge our custom additions database
        if os.path.exists(CUSTOM_DB):
            _log("Loading custom database: {}".format(CUSTOM_DB))
            try:
                with open(CUSTOM_DB, 'rb') as f:
                    custom_repo = self._parse(f.read())
                self._merge(main_repo, custom_repo)
                _log("Custom database merged ({} libraries total).".format(
                    len(main_repo.libraries)))
            except Exception as e:
                _log("WARNING: Could not load custom database: {}".format(str(e)))

        return main_repo

    def _merge(self, main_repo, custom_repo):
        """Merge custom_repo into main_repo in-place."""
        index = {lib.name: lib for lib in main_repo.libraries}
        for lib in custom_repo.libraries:
            if lib.name in index:
                existing = index[lib.name]
                existing.vulnerabilities.extend(lib.vulnerabilities)
                existing.uris.extend(lib.uris)
                existing.filename.extend(lib.filename)
                existing.file_contents.extend(lib.file_contents)
                existing.hashes.update(lib.hashes)
                existing.functions.extend(lib.functions)
                existing.headers.extend(lib.headers)
            else:
                main_repo.libraries.append(lib)
                index[lib.name] = lib

    def _parse(self, data):
        if isinstance(data, bytes):
            data = data.decode('utf-8')
        root = json.loads(data)
        repo = VulnerabilitiesRepository()
        for name, lib_json in root.items():
            lib = JsLibrary(name)
            for vuln_json in lib_json.get('vulnerabilities', []):
                identifiers = vuln_json.get('identifiers', {})
                norm_ids = {}
                for k, v in identifiers.items():
                    norm_ids[k] = v if isinstance(v, list) else [v]
                lib.vulnerabilities.append(JsVulnerability(
                    at_or_above=vuln_json.get('atOrAbove'),
                    below=vuln_json.get('below'),
                    info=vuln_json.get('info', []),
                    identifiers=norm_ids,
                    severity=vuln_json.get('severity', 'medium'),
                ))
            extractors = lib_json.get('extractors', {})
            lib.uris          = [_replace_version(p) for p in extractors.get('uri', [])]
            lib.filename      = [_replace_version(p) for p in extractors.get('filename', [])]
            lib.file_contents = [_replace_version(p) for p in extractors.get('filecontent', [])]
            lib.hashes        = extractors.get('hashes', {})
            lib.functions     = extractors.get('func', [])
            lib.headers       = extractors.get('headers', [])
            repo.libraries.append(lib)
        return repo


# ---------------------------------------------------------------------------
# Scanner  (mirrors ScannerFacade.java)
# ---------------------------------------------------------------------------

class Scanner(object):
    def __init__(self, repo):
        self._repo = repo

    def scan_script(self, path, content_bytes, offset=0):
        """Multi-stage detection: URI → filename → hash → content."""
        # 1. URI / full path
        results = self._repo.find_by_uri(path)
        if results:
            return results

        # 2. Filename only
        filename = path.rsplit('/', 1)[-1]
        results = self._repo.find_by_filename(filename)
        if results:
            return results

        body = bytes(content_bytes[offset:]) if offset else bytes(content_bytes)

        # 3. SHA-1 hash
        file_hash = hashlib.sha1(body).hexdigest()
        results = self._repo.find_by_hash(file_hash)
        if results:
            return results

        # 4. File content
        content_str = body.decode('utf-8', errors='replace')
        return self._repo.find_by_file_content(content_str)

    def scan_headers(self, headers):
        """Detect software via HTTP response headers (e.g. Server: nginx/x.y.z)."""
        return self._repo.find_by_headers(headers)

    def scan_html(self, content_bytes, offset=0):
        """Extract <script src="..."> URLs and scan each by path/filename."""
        body = bytes(content_bytes[offset:]) if offset else bytes(content_bytes)
        html = body.decode('utf-8', errors='replace')
        results = []
        for url in self._find_script_urls(html):
            found = self._repo.find_by_uri(url)
            if not found:
                filename = url.rsplit('/', 1)[-1]
                found = self._repo.find_by_filename(filename)
            results.extend(found)
        return results

    @staticmethod
    def _find_script_urls(html):
        urls = []
        for chunk in html.split('</'):
            if '<script' in chunk or '<SCRIPT' in chunk:
                m = _SCRIPT_SRC_RE.search(chunk)
                if m:
                    urls.append(m.group(1))
        return urls


# ---------------------------------------------------------------------------
# Burp issue  (mirrors VulnerableLibraryIssue.java)
# ---------------------------------------------------------------------------

class VulnerableLibraryIssue(IScanIssue):
    def __init__(self, http_service, url, http_messages, lib_result, path):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._path = path

        lib = lib_result.library
        vuln = lib_result.vuln
        self._lib_name = lib.name
        if lib_result.via_header:
            self._name = "Vulnerable software: {}".format(lib.name)
        else:
            self._name = "Vulnerable JavaScript library: {}".format(lib.name)
        self._severity = _map_severity(vuln.severity)
        self._detail = _build_detail(lib.name, lib_result.version, vuln)

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Tentative"

    def getIssueBackground(self):
        return None

    def getRemediationBackground(self):
        return None

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        return None

    def getHttpMessages(self):
        return self._http_messages

    def getHttpService(self):
        return self._http_service

    def same_as(self, other):
        return (
            isinstance(other, VulnerableLibraryIssue)
            and self._lib_name == other._lib_name
            and self._path == other._path
        )


def _map_severity(severity):
    return {
        'critical': 'High',
        'high':     'High',
        'medium':   'Medium',
        'low':      'Low',
        'info':     'Information',
    }.get((severity or '').lower(), 'Medium')


def _build_detail(lib_name, version, vuln):
    links = ''.join(
        '<li><a href="{u}">{u}</a></li>'.format(u=u) for u in vuln.info
    )
    version_range = ''
    if vuln.at_or_above:
        version_range += ' at or above {}'.format(vuln.at_or_above)
    if vuln.below:
        version_range += ' below {}'.format(vuln.below)

    ids_html = ''
    for id_type, id_list in (vuln.identifiers or {}).items():
        ids_html += '<b>{}:</b> {}<br>'.format(id_type, ', '.join(id_list))

    return (
        '<p>The library <b>{lib}</b> version <b>{ver}</b> was detected. '
        'This version is known to be vulnerable{range}.</p>'
        '{ids}'
        '<p>References:<ul>{links}</ul></p>'
        '<p><i>This finding is tentative — manual verification is recommended '
        'to confirm exploitability.</i></p>'
    ).format(
        lib=lib_name,
        ver=version,
        range=version_range,
        ids=ids_html,
        links=links,
    )


# ---------------------------------------------------------------------------
# Burp extension entry point  (mirrors BurpExtender.java)
# ---------------------------------------------------------------------------

class BurpExtender(IBurpExtender, IScannerCheck, IProxyListener):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Retire.js")

        stdout = callbacks.getStdout()

        def _print(msg):
            try:
                stdout.write((msg + '\n').encode('utf-8'))
            except Exception:
                pass

        self._print = _print

        _print("== Retire.js ==")
        _print("Passive scanner for vulnerable JavaScript libraries")
        _print("  Database: " + REPO_URL)

        self._scanner = None
        self._reported = set()  # (host, path, lib_name) — dedup for proxy-triggered issues
        try:
            repo = DatabaseLoader().load(log=_print)
            self._scanner = Scanner(repo)
            _print("Database loaded ({} libraries).".format(len(repo.libraries)))
        except Exception as e:
            _print("ERROR: Could not load database: {}".format(str(e)))

        callbacks.registerProxyListener(self)
        callbacks.registerScannerCheck(self)
        _print("Retire.js loaded.")

    # ------------------------------------------------------------------
    # IProxyListener — fires on every proxied response automatically
    # ------------------------------------------------------------------

    def processProxyMessage(self, messageIsRequest, message):
        if messageIsRequest or self._scanner is None:
            return
        try:
            http_msg = message.getMessageInfo()
            issues = self._run_passive_checks(http_msg)
            host = str(http_msg.getHttpService().getHost())
            for issue in issues:
                key = (host, issue._path, issue._lib_name)
                if key not in self._reported:
                    self._reported.add(key)
                    self._callbacks.addScanIssue(issue)
                    break  # one issue per library per path is enough
        except Exception as e:
            self._print("ERROR in proxy listener: {}".format(str(e)))

    # ------------------------------------------------------------------
    # IScannerCheck — fires during explicit passive scans
    # ------------------------------------------------------------------

    def doPassiveScan(self, base_rr):
        if self._scanner is None:
            return []
        return self._run_passive_checks(base_rr)

    def doActiveScan(self, base_rr, insertion_point):
        return []

    def consolidateDuplicateIssues(self, existing, new):
        if (isinstance(existing, VulnerableLibraryIssue)
                and isinstance(new, VulnerableLibraryIssue)):
            return -1 if existing.same_as(new) else 0
        return 0

    # ------------------------------------------------------------------
    # Core scan logic shared by both entry points
    # ------------------------------------------------------------------

    def _run_passive_checks(self, base_rr):
        resp_bytes = base_rr.getResponse()
        if not resp_bytes:
            return []

        resp_info = self._helpers.analyzeResponse(resp_bytes)
        req_info = self._helpers.analyzeRequest(
            base_rr.getHttpService(), base_rr.getRequest()
        )

        path = _get_path(req_info)
        content_type = _get_content_type(resp_info)
        offset = resp_info.getBodyOffset()

        all_headers = [str(h) for h in resp_info.getHeaders()]
        issues = []

        # Header-based detection runs on every response
        try:
            header_results = self._scanner.scan_headers(all_headers)
            issues.extend(self._build_issues(header_results, base_rr, req_info, path))
        except Exception as e:
            self._print("ERROR in header scan for {}: {}".format(path, str(e)))

        # Content-based detection for JS and HTML responses
        try:
            if 'javascript' in content_type or path.endswith('.js'):
                results = self._scanner.scan_script(path, resp_bytes, offset)
                issues.extend(self._build_issues(results, base_rr, req_info, path))
            elif 'html' in content_type or path.endswith(HTML_EXTENSIONS):
                results = self._scanner.scan_html(resp_bytes, offset)
                issues.extend(self._build_issues(results, base_rr, req_info, path))
        except Exception as e:
            self._print("ERROR scanning {}: {}".format(path, str(e)))

        return issues

    # ------------------------------------------------------------------

    def _build_issues(self, results, base_rr, req_info, path):
        issues = []
        http_service = base_rr.getHttpService()
        url = req_info.getUrl()
        for result in results:
            pattern = result.regex_response or result.regex_request
            highlighted = self._highlight(base_rr, pattern)
            issues.append(VulnerableLibraryIssue(
                http_service=http_service,
                url=url,
                http_messages=[highlighted],
                lib_result=result,
                path=path,
            ))
        return issues

    def _highlight(self, base_rr, pattern):
        """Mark the matching pattern in the HTTP response for display in Burp."""
        if not pattern:
            return base_rr
        try:
            resp_bytes = base_rr.getResponse()
            if resp_bytes is None:
                return base_rr
            resp_str = self._helpers.bytesToString(resp_bytes)
            m = re.search(pattern, resp_str)
            if m:
                from jarray import array
                marker = array([m.start(), m.end()], 'i')
                return self._callbacks.applyMarkers(base_rr, None, [marker])
        except:
            pass
        return base_rr


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_content_type(resp_info):
    for header in resp_info.getHeaders():
        if header.lower().startswith('content-type:'):
            return header[13:].lower()
    return ''


def _get_path(req_info):
    first = req_info.getHeaders()[0]
    # "GET /path/to/file.js HTTP/1.1" → "/path/to/file.js"
    return first.split(' ', 1)[1].rsplit(' ', 1)[0]
