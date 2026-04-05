#!/usr/bin/env python3
"""Generate docs/DOCUMENTATION.md from comments in project Go sources."""
import re
import unicodedata
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent

SOURCES = [
    PROJECT_ROOT / "main.go",
    *sorted((PROJECT_ROOT / "api").glob("*.go")),
]
OUT_DIR = PROJECT_ROOT / "docs"
OUT_FILE = OUT_DIR / "DOCUMENTATION.md"

# ── Category definitions ────────────────────────────────────────────────────
# Each entry: (display title, list of symbol selectors).
# A selector is either:
# - "Name" (matches func/type by name)
# - ("func", "Name") or ("type", "Name") to match precisely.
CATEGORIES = [
    ("CLI", {
        ("type", "searchOptions"),
        ("type", "searchOutput"),
        ("func", "parseSearchArgs"),
        ("func", "formatLine"),
        ("func", "fetchPageWithRetry"),
        ("func", "runHost"),
        ("func", "runSearch"),
        ("func", "main"),
    }),
    ("API Client Core", {
        ("type", "Client"),
        ("type", "Option"),
        ("func", "NewClient"),
        ("func", "WithBaseURL"),
        "BaseURL",
    }),
    ("API Models", {
        ("type", "APIInfo"),
        ("type", "HostLocation"),
        ("type", "HostHTTP"),
        ("type", "Meta"),
        ("type", "Host"),
        ("type", "FacetCount"),
        ("type", "SearchResult"),
    }),
    ("API Operations", {
        ("func", "GetAPIInfo"),
        ("func", "SearchHosts"),
        ("func", "GetHostByIP"),
    }),
    ("Compatibility Aliases", {
        ("func", "APIInfo"),
        ("func", "HostSearch"),
        ("func", "HostLookup"),
        ("func", "New"),
    }),
]

COMMAND_REFERENCE = [
    ("host <ip>", "Fetch detailed host metadata for one IP address."),
    ("search [--page N] <query>", "Run one paginated search request and print results."),
    ("search --all <query>", "Iterate all pages for a query (consumes query credits)."),
    ("search --out <file> <query>", "Save full JSON output to a file with safe path checks."),
]

API_CONTRACTS = [
    ("GetAPIInfo(ctx)", "ctx context.Context", "*APIInfo", "network error, non-200 API status, JSON decode error"),
    ("SearchHosts(ctx, query, page)", "ctx context.Context, query string, page >= 1", "*SearchResult", "network error, non-200 API status, JSON decode error"),
    ("GetHostByIP(ctx, ip)", "ctx context.Context, IPv4/IPv6 as string", "*Host", "network error, non-200 API status, JSON decode error"),
]

OPERATION_MODEL_LINKS = [
    ("GetAPIInfo()", "APIInfo"),
    ("SearchHosts()", "SearchResult, Host, FacetCount"),
    ("GetHostByIP()", "Host, HostLocation, HostHTTP, Meta"),
]

# ── Parsing ──────────────────────────────────────────────────────────────────

def parse_source(src_path: Path):
    """Return parsed info from one Go source file."""
    src_text = src_path.read_text(encoding="utf-8")
    lines = src_text.splitlines()
    blocks = []
    comment_buf: list[str] = []
    package_comments: list[str] = []
    package_name = ""
    saw_package = False

    func_re = re.compile(r"^\s*func\s*(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)")
    type_re = re.compile(r"^\s*type\s+([A-Za-z_][A-Za-z0-9_]*)")
    package_re = re.compile(r"^\s*package\s+(\w+)")

    for line in lines:
        stripped = line.lstrip()

        # Accumulate comment lines
        if stripped.startswith("//"):
            text = stripped[2:]
            if text.startswith(" "):
                text = text[1:]
            comment_buf.append(text)
            continue

        # Package declaration — grab preceding comments as package-level doc
        package_match = package_re.match(line)
        if not saw_package and package_match:
            saw_package = True
            package_name = package_match.group(1)
            if comment_buf:
                package_comments = comment_buf[:]
            comment_buf = []
            continue

        # Function declaration
        m = func_re.match(line)
        if m:
            blocks.append({
                "kind": "func",
                "name": m.group(1),
                "comment": "\n".join(comment_buf).strip(),
                "source": str(src_path.relative_to(PROJECT_ROOT)),
                "package": package_name,
            })
            comment_buf = []
            continue

        # Type declaration
        m = type_re.match(line)
        if m:
            blocks.append({
                "kind": "type",
                "name": m.group(1),
                "comment": "\n".join(comment_buf).strip(),
                "source": str(src_path.relative_to(PROJECT_ROOT)),
                "package": package_name,
            })
            comment_buf = []
            continue

        # Any other non-comment line resets the buffer
        comment_buf = []

    return {
        "source": str(src_path.relative_to(PROJECT_ROOT)),
        "package": package_name,
        "package_comments": package_comments,
        "blocks": blocks,
    }


def collect_sources():
    """Parse all configured source files and return package docs and blocks."""
    parsed = [parse_source(src) for src in SOURCES if src.exists()]
    package_docs: dict[str, list[str]] = {}
    blocks: list[dict] = []

    for item in parsed:
        blocks.extend(item["blocks"])
        if item["package"] and item["package_comments"] and item["package"] not in package_docs:
            package_docs[item["package"]] = item["package_comments"]

    return package_docs, blocks


# ── Grouping ─────────────────────────────────────────────────────────────────

def group_blocks(blocks: list[dict]):
    """Return an ordered list of (category_title, [block, ...])."""
    def is_selected(block: dict, selectors: set):
        keyed = (block["kind"], block["name"])
        return keyed in selectors or block["name"] in selectors

    used_indices: set[int] = set()
    grouped = []

    for title, names in CATEGORIES:
        members = []
        for idx, block in enumerate(blocks):
            if idx in used_indices:
                continue
            if is_selected(block, names):
                members.append(block)
                used_indices.add(idx)
        if members:
            grouped.append((title, members))

    # Anything not explicitly categorised goes into "Other"
    remainder = [b for idx, b in enumerate(blocks) if idx not in used_indices]
    if remainder:
        grouped.append(("Other", remainder))

    return grouped


# ── Helpers ───────────────────────────────────────────────────────────────────

def slugify(text: str) -> str:
    """Convert a section title to a GitHub-flavoured Markdown anchor slug.

    Handles Unicode by stripping diacritics, lowercasing, replacing spaces
    with hyphens, and dropping everything that isn't alphanumeric or a hyphen.
    Much more robust than a handful of manual .replace() calls.
    """
    # Normalise to NFD so accented chars decompose (é → e + combining accent)
    nfd = unicodedata.normalize("NFD", text)
    # Drop combining characters (the accent parts)
    ascii_text = "".join(c for c in nfd if unicodedata.category(c) != "Mn")
    lower = ascii_text.lower()
    # Replace spaces and & with hyphens
    slug = re.sub(r"[\s&]+", "-", lower)
    # Drop anything that isn't a letter, digit, or hyphen
    slug = re.sub(r"[^a-z0-9\-]", "", slug)
    # Collapse multiple hyphens
    slug = re.sub(r"-+", "-", slug).strip("-")
    return "#" + slug


# ── Rendering ─────────────────────────────────────────────────────────────────

def _signature(block: dict) -> str:
    """Return display name: 'TypeName' for types, 'funcName()' for funcs."""
    if block["kind"] == "type":
        return block["name"]
    return f"{block['name']}()"


def render_md(package_docs: dict[str, list[str]], blocks: list[dict]):
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    grouped = group_blocks(blocks)

    # Build table-of-contents entries
    toc_entries = [
        ("Quick start", "#quick-start"),
        ("Command reference", "#command-reference"),
        ("API method contracts", "#api-method-contracts"),
        ("Operation → model mapping", "#operation--model-mapping"),
        ("Error handling & limits", "#error-handling--limits"),
    ]
    if package_docs:
        toc_entries.append(("Package overview", "#package-overview"))
    for title, _ in grouped:
        toc_entries.append((title, slugify(title)))

    with OUT_FILE.open("w", encoding="utf-8") as f:

        # Header
        f.write("# Shodan-Go — Code Documentation\n\n")

        # Table of contents
        f.write("## Table of contents\n\n")
        for idx, (label, anchor) in enumerate(toc_entries, 1):
            f.write(f"{idx}. [{label}]({anchor})\n")
        f.write("\n---\n\n")

        # Quick start
        f.write("## Quick start\n\n")
        f.write("```go\n")
        f.write("apiKey := os.Getenv(\"SHODAN_API_KEY\")\n")
        f.write("client := shodan.NewClient(apiKey)\n\n")
        f.write("ctx := context.Background()\n\n")
        f.write("info, err := client.GetAPIInfo(ctx)\n")
        f.write("if err != nil {\n")
        f.write("    log.Fatal(err)\n")
        f.write("}\n\n")
        f.write("host, err := client.GetHostByIP(ctx, \"8.8.8.8\")\n")
        f.write("if err != nil {\n")
        f.write("    log.Fatal(err)\n")
        f.write("}\n")
        f.write("fmt.Println(host.IPString, host.Org)\n")
        f.write("```\n\n")
        f.write("---\n\n")

        # Command reference
        f.write("## Command reference\n\n")
        f.write("| Command | Purpose |\n")
        f.write("|---------|---------|\n")
        for command, purpose in COMMAND_REFERENCE:
            f.write(f"| `{command}` | {purpose} |\n")
        f.write("\n---\n\n")

        # API contracts
        f.write("## API method contracts\n\n")
        f.write("| Method | Input | Output | Errors |\n")
        f.write("|--------|-------|--------|--------|\n")
        for method, method_input, output, errors in API_CONTRACTS:
            f.write(f"| `{method}` | {method_input} | {output} | {errors} |\n")
        f.write("\n---\n\n")

        # Operation to model mapping
        f.write("## Operation → model mapping\n\n")
        f.write("| Operation | Main models involved |\n")
        f.write("|-----------|-----------------------|\n")
        for operation, models in OPERATION_MODEL_LINKS:
            f.write(f"| `{operation}` | {models} |\n")
        f.write("\n---\n\n")

        # Errors and limits
        f.write("## Error handling & limits\n\n")
        f.write("- All API calls return an error for network failures and non-200 Shodan responses.\n")
        f.write("- All errors include operation context: `GetAPIInfo: decode response: ...`.\n")
        f.write("- Network errors are sanitized — the API key is **never** included in error messages.\n")
        f.write("- Search pagination uses 100 results per page; `--all` consumes additional query credits.\n")
        f.write("- CLI exits early when `SHODAN_API_KEY` is missing.\n")
        f.write("- `--out` path is sanitized: only relative paths inside the current directory are accepted.\n\n")
        f.write("### Security notes\n\n")
        f.write("| Concern | Mitigation |\n")
        f.write("|---------|------------|\n")
        f.write("| API key in URLs | Encoded via `url.Values`, never raw in `fmt.Sprintf` |\n")
        f.write("| API key in error logs | Stripped by `sanitizeErr` via `*url.Error` unwrap |\n")
        f.write("| IP path injection | Input encoded with `url.PathEscape` before use in URL |\n")
        f.write("| Output path traversal | `filepath.Clean` + dotdot traversal check (absolute paths allowed) |\n")
        f.write("| Context / timeout | Every HTTP call uses `context.Context` + 30 s client timeout |\n")
        f.write("\n")
        f.write("- Example (`SHODAN_API_KEY` missing): `SHODAN_API_KEY environment variable not set`.\n")
        f.write("- Example (API non-200): `GetHostByIP 8.8.8.8: shodan API error: 404 Not Found`.\n\n")
        f.write("---\n\n")

        # Package-level overview
        if package_docs:
            f.write("## Package overview\n\n")
            for package_name, comments in sorted(package_docs.items()):
                f.write(f"### `{package_name}`\n\n")
                f.write("\n".join(comments) + "\n\n")
            f.write("---\n\n")

        # Grouped sections
        for title, members in grouped:
            f.write(f"## {title}\n\n")

            # Summary table
            f.write("| Symbol | Source | Description |\n")
            f.write("|--------|--------|-------------|\n")
            for b in members:
                sig = _signature(b)
                desc = b["comment"].splitlines()[0] if b["comment"] else "_No description provided._"
                desc = desc.replace("|", "\\|")
                f.write(f"| `{sig}` | `{b['source']}` | {desc} |\n")
            f.write("\n")

            # Detailed entries
            for b in members:
                sig = _signature(b)
                f.write(f"### `{sig}`\n\n")
                if b["comment"]:
                    f.write(b["comment"] + "\n\n")
                else:
                    f.write("_No comment provided._\n\n")

            f.write("---\n\n")

    print(f"Generated {OUT_FILE}")


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> int:
    missing = [src for src in SOURCES if not src.exists()]
    if missing:
        for src in missing:
            print(f"Warning: source file '{src}' not found — skipping.")

    package_docs, blocks = collect_sources()

    if not blocks:
        print("Error: no functions or types found in configured source files.")
        return 1

    render_md(package_docs, blocks)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())