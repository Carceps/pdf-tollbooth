import json
import os
import secrets
import smtplib
import sqlite3
from contextlib import asynccontextmanager
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import fitz  # PyMuPDF
import stripe
import uvicorn
from fastapi import Depends, FastAPI, File, HTTPException, Request, Security, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field


DATABASE_PATH = Path(__file__).resolve().parent / "nexus_api.db"

FREE_TRIAL_API_KEY = "nx_free_trial"


def init_db() -> None:
    """Create schema and seed default keys. (Do not alter core query semantics here.)"""
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                key TEXT PRIMARY KEY,
                label TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "INSERT OR IGNORE INTO api_keys (key, label) VALUES (?, ?)",
            ("pay_me_123", "admin"),
        )
        conn.commit()
    finally:
        conn.close()


def get_db() -> sqlite3.Connection:
    """Yield a SQLite connection per request."""
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    try:
        yield conn
    finally:
        conn.close()


def persist_api_key_from_webhook(key: str, label: str) -> None:
    """Store a webhook-issued key in SQLite (authorization source for /extract)."""
    conn = sqlite3.connect(DATABASE_PATH, check_same_thread=False)
    try:
        conn.execute(
            "INSERT OR REPLACE INTO api_keys (key, label) VALUES (?, ?)",
            (key, label),
        )
        conn.commit()
    finally:
        conn.close()


def send_api_key_email(recipient_email: str | None, api_key: str) -> None:
    """
    Send the issued API key to the customer via Gmail SMTP.
    Requires GMAIL_ADDRESS and GMAIL_APP_PASSWORD environment variables.
    """
    gmail_address = os.getenv("GMAIL_ADDRESS")
    gmail_app_password = os.getenv("GMAIL_APP_PASSWORD")
    if not gmail_address or not gmail_app_password:
        print(
            "WARNING: GMAIL_ADDRESS or GMAIL_APP_PASSWORD is not set; "
            "skipping API key email delivery."
        )
        return

    if not recipient_email:
        print("WARNING: No recipient email address; skipping API key email delivery.")
        return

    message = EmailMessage()
    message["Subject"] = "Your Nexus Extract API Key"
    message["From"] = gmail_address
    message["To"] = recipient_email
    message.set_content(
        f"Your Nexus Extract API key:\n\n{api_key}\n\n"
        f"Documentation:\nhttps://pdf-tollbooth.onrender.com/docs\n"
    )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(gmail_address, gmail_app_password)
        smtp.send_message(message)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="Nexus Extract API",
    description="Enterprise-grade structured data extraction for financial and legal documents.",
    version="1.0.0",
    docs_url="/docs",
    lifespan=lifespan,
)

stripe.api_key = (
    "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"
)

# Maps API key -> label (e.g. role or customer id). Webhook adds new keys after checkout.
VALID_API_KEYS = {"pay_me_123": "admin"}

api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)


def verify_api_key(
    api_key: str | None = Security(api_key_header),
    conn: sqlite3.Connection = Depends(get_db),
) -> str:
    """
    Require a valid API key: built-in free trial key bypasses the database;
    otherwise the key must exist in the api_keys table.
    Raises HTTP 401 Unauthorized if missing or invalid.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="Unauthorized")
    if api_key == FREE_TRIAL_API_KEY:
        return FREE_TRIAL_API_KEY
    row = conn.execute(
        "SELECT 1 FROM api_keys WHERE key = ? LIMIT 1",
        (api_key,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return api_key


def table_key(table):
    """
    Build a stable key from table bounds to deduplicate repeated detections.
    """
    x0, y0, x1, y1 = table.bbox
    return (round(x0, 1), round(y0, 1), round(x1, 1), round(y1, 1))


class ExtractTableItem(BaseModel):
    """One detected table on a single PDF page."""

    page: int = Field(..., description="1-based page index in the uploaded PDF.")
    table_number_on_page: int = Field(
        ...,
        description="Ordinal of this table among tables detected on the same page.",
    )
    bbox: list[float] = Field(
        ...,
        description="Table bounding box in PDF coordinates (x0, y0, x1, y1).",
    )
    rows: list[list[Any]] = Field(
        ...,
        description="Cell matrix: each inner list is one row of cell values (strings or nulls).",
    )


class ExtractResponse(BaseModel):
    """Aggregated extraction result for the whole document."""

    pages_scanned: int = Field(..., description="Number of PDF pages actually processed.")
    total_tables_extracted: int = Field(
        ...,
        description="Count of distinct lined tables extracted across processed pages.",
    )
    tables: list[ExtractTableItem] = Field(
        ...,
        description="Per-table payloads including row/column cell text.",
    )
    warning: str | None = Field(
        None,
        description="Set when free-trial page limit applies (multi-page PDF truncated to page 1).",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "pages_scanned": 1,
                "total_tables_extracted": 1,
                "tables": [
                    {
                        "page": 1,
                        "table_number_on_page": 1,
                        "bbox": [72.0, 120.5, 520.0, 400.0],
                        "rows": [
                            ["Account", "Balance", "Currency"],
                            ["Operating", "125000.00", "USD"],
                        ],
                    },
                ],
                "warning": (
                    "Free trial mode: only page 1 was processed. This PDF has 12 pages; "
                    "upgrade to Pro for full-document extraction."
                ),
            }
        }
    )


@app.get("/", response_class=HTMLResponse)
async def landing_page():
    html_content = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Nexus Extract API — PDF tables to JSON</title>
    <style>
        :root {
            --bg: #0a0a0f;
            --surface: #12121a;
            --border: #2a2a35;
            --text: #e8e8ed;
            --muted: #8b8b9a;
            --accent: #22d3ee;
            --accent2: #a78bfa;
            --terminal-bg: #0d1117;
            --terminal-green: #3fb950;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            min-height: 100vh;
        }
        .gradient-orb {
            position: fixed;
            width: 600px;
            height: 600px;
            border-radius: 50%;
            background: radial-gradient(circle, rgba(34,211,238,0.12) 0%, transparent 70%);
            top: -200px;
            right: -150px;
            pointer-events: none;
            z-index: 0;
        }
        .wrap { max-width: 1100px; margin: 0 auto; padding: 0 24px; position: relative; z-index: 1; }
        nav {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 20px 0;
            border-bottom: 1px solid var(--border);
        }
        .logo { font-weight: 700; font-size: 1.1rem; letter-spacing: -0.02em; }
        .logo span { color: var(--accent); }
        nav a.docs { color: var(--muted); text-decoration: none; font-size: 0.9rem; }
        nav a.docs:hover { color: var(--accent); }
        .hero {
            padding: 72px 0 56px;
            text-align: center;
        }
        .hero h1 {
            font-size: clamp(2rem, 5vw, 3rem);
            font-weight: 800;
            letter-spacing: -0.03em;
            line-height: 1.15;
            margin-bottom: 16px;
            background: linear-gradient(135deg, #fff 0%, #94a3b8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        .hero .sub {
            color: var(--muted);
            font-size: 1.15rem;
            max-width: 560px;
            margin: 0 auto 32px;
        }
        .hero-cta {
            display: inline-flex;
            gap: 12px;
            flex-wrap: wrap;
            justify-content: center;
        }
        .btn {
            display: inline-block;
            padding: 12px 24px;
            border-radius: 10px;
            font-weight: 600;
            text-decoration: none;
            transition: transform 0.15s, box-shadow 0.15s;
        }
        .btn-primary {
            background: linear-gradient(135deg, var(--accent), #06b6d4);
            color: #0a0a0f;
        }
        .btn-primary:hover { transform: translateY(-2px); box-shadow: 0 8px 24px rgba(34,211,238,0.25); }
        .btn-ghost {
            border: 1px solid var(--border);
            color: var(--text);
        }
        .btn-ghost:hover { border-color: var(--accent); color: var(--accent); }
        section { padding: 56px 0; }
        section h2 {
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 28px;
            text-align: center;
        }
        .how-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 20px;
        }
        .card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 14px;
            padding: 24px;
        }
        .card .step { color: var(--accent); font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; margin-bottom: 8px; }
        .card h3 { font-size: 1.05rem; margin-bottom: 8px; }
        .card p { color: var(--muted); font-size: 0.95rem; }
        .terminal-wrap { max-width: 720px; margin: 0 auto; }
        .terminal {
            background: var(--terminal-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 24px 48px rgba(0,0,0,0.45);
        }
        .terminal-bar {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 12px 16px;
            background: #161b22;
            border-bottom: 1px solid var(--border);
        }
        .dot { width: 12px; height: 12px; border-radius: 50%; }
        .dot.r { background: #ff5f56; }
        .dot.y { background: #ffbd2e; }
        .dot.g { background: #27c93f; }
        .terminal-title { flex: 1; text-align: center; font-size: 0.75rem; color: var(--muted); }
        pre.terminal-body {
            padding: 20px 22px;
            font-family: "JetBrains Mono", "Fira Code", Consolas, monospace;
            font-size: 0.8rem;
            line-height: 1.55;
            overflow-x: auto;
            color: #c9d1d9;
        }
        .kw { color: #ff7b72; }
        .fn { color: #d2a8ff; }
        .str { color: #a5d6ff; }
        .key { color: var(--terminal-green); }
        .cmt { color: #8b949e; }
        .pricing {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            max-width: 800px;
            margin: 0 auto;
        }
        @media (max-width: 700px) { .pricing { grid-template-columns: 1fr; } }
        .price-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 28px;
            display: flex;
            flex-direction: column;
        }
        .price-card.pro {
            border-color: rgba(34,211,238,0.35);
            box-shadow: 0 0 0 1px rgba(34,211,238,0.08);
        }
        .price-card h3 { font-size: 1.25rem; margin-bottom: 8px; }
        .price { font-size: 2rem; font-weight: 800; margin: 12px 0; }
        .price small { font-size: 1rem; font-weight: 500; color: var(--muted); }
        .price-card ul { list-style: none; color: var(--muted); font-size: 0.95rem; margin: 16px 0 24px; flex: 1; }
        .price-card ul li { padding: 6px 0; padding-left: 22px; position: relative; }
        .price-card ul li::before { content: "✓"; position: absolute; left: 0; color: var(--accent); }
        footer { padding: 40px 0; text-align: center; color: var(--muted); font-size: 0.85rem; border-top: 1px solid var(--border); }
    </style>
</head>
<body>
    <div class="gradient-orb"></div>
    <div class="wrap">
        <nav>
            <div class="logo">Nexus<span>Extract</span></div>
            <a class="docs" href="/docs">API docs →</a>
        </nav>
        <header class="hero">
            <h1>Structured tables from messy PDFs</h1>
            <p class="sub">Vector-accurate, line-based table detection. Multi-page extraction, JSON responses, and a free trial key—built for developers shipping document pipelines.</p>
            <div class="hero-cta">
                <a class="btn btn-primary" href="https://buy.stripe.com/4gM8wP9J16HCgmxcas6EU03">Upgrade to Pro — $49/mo</a>
                <a class="btn btn-ghost" href="/docs">Open Swagger</a>
            </div>
        </header>

        <section>
            <h2>How it works</h2>
            <div class="how-grid">
                <div class="card">
                    <div class="step">01</div>
                    <h3>Upload a PDF</h3>
                    <p>POST your file to <code>/extract</code> with <code>multipart/form-data</code> and your API key in <code>x-api-key</code>.</p>
                </div>
                <div class="card">
                    <div class="step">02</div>
                    <h3>Detect lined tables</h3>
                    <p>PyMuPDF finds real grid lines—not guessed whitespace—so you get finance-grade structure, not paragraph soup.</p>
                </div>
                <div class="card">
                    <div class="step">03</div>
                    <h3>Get JSON rows</h3>
                    <p>Receive page numbers, bounding boxes, and a <code>rows</code> matrix per table, ready for pandas, DBs, or LLMs.</p>
                </div>
            </div>
        </section>

        <section>
            <h2>Try it with Python</h2>
            <div class="terminal-wrap">
                <div class="terminal">
                    <div class="terminal-bar">
                        <span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>
                        <span class="terminal-title">example.py</span>
                    </div>
<pre class="terminal-body"><span class="kw">import</span> requests

url = <span class="str">"https://your-api.example.com/extract"</span>
headers = {<span class="str">"x-api-key"</span>: <span class="key">"nx_free_trial"</span>}
files = {<span class="str">"file"</span>: open(<span class="str">"report.pdf"</span>, <span class="str">"rb"</span>)}

r = requests.post(url, headers=headers, files=files)
<span class="kw">print</span>(r.json())  <span class="cmt"># pages_scanned, tables[].rows, ...</span></pre>
                </div>
            </div>
        </section>

        <section>
            <h2>Pricing</h2>
            <div class="pricing">
                <div class="price-card">
                    <h3>Free trial</h3>
                    <p style="color:var(--muted);font-size:0.95rem;">Public demo key — no signup</p>
                    <div class="price">$0 <small>/ forever</small></div>
                    <ul>
                        <li>Use header <code style="color:var(--accent);">nx_free_trial</code></li>
                        <li>First page only per PDF</li>
                        <li>Same JSON schema as Pro</li>
                    </ul>
                    <a class="btn btn-ghost" href="/docs" style="text-align:center;">Read the docs</a>
                </div>
                <div class="price-card pro">
                    <h3>Pro</h3>
                    <p style="color:var(--muted);font-size:0.95rem;">Full document extraction</p>
                    <div class="price">$49 <small>/ month</small></div>
                    <ul>
                        <li>All pages in every upload</li>
                        <li>Private API key via checkout</li>
                        <li>Email delivery of your key</li>
                    </ul>
                    <a class="btn btn-primary" href="https://buy.stripe.com/4gM8wP9J16HCgmxcas6EU03" style="text-align:center;">Get Pro access</a>
                </div>
            </div>
        </section>

        <footer>
            Nexus Extract API · Enterprise PDF table extraction
        </footer>
    </div>
</body>
</html>
    """
    return html_content


@app.post(
    "/extract",
    response_model=ExtractResponse,
    summary="Extract vector-lined tables from a PDF",
    description=(
        "Upload a PDF document. The engine detects tables using PyMuPDF's strict **line-based** "
        "strategy (`strategy='lines'`).\n\n"
        "**Authentication:** send `x-api-key`. Use `nx_free_trial` for a free first-page-only "
        "extraction, or a key from your account (issued after purchase) for full-document scans.\n\n"
        "The response includes `tables` with page numbers, bounding boxes, and **rows** matrices. "
        "A **warning** field appears for free trial when the PDF has more than one page."
    ),
    responses={
        400: {"description": "Bad request — invalid file type or unreadable PDF."},
        401: {"description": "Unauthorized — missing or invalid API key."},
    },
)
async def extract_pdf(
    file: UploadFile = File(
        ...,
        description="PDF file to analyze (Content-Type must be application/pdf).",
    ),
    api_key: str = Depends(verify_api_key),
):
    """
    Accept a PDF upload, scan page(s), and extract strict vector-lined tables.
    Free trial key processes only page 1; paid keys process the full document.
    """
    if file.content_type != "application/pdf":
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid file type: this endpoint only accepts PDF uploads. "
                "Send Content-Type 'application/pdf' (multipart file field 'file')."
            ),
        )

    try:
        pdf_bytes = await file.read()
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Unable to read PDF: {exc}") from exc

    total_pages_in_document = len(doc)
    is_free_trial = api_key == FREE_TRIAL_API_KEY

    if is_free_trial:
        page_indices = [0]
        warning = None
        if total_pages_in_document > 1:
            warning = (
                "Free trial mode: only page 1 was processed. "
                f"This PDF has {total_pages_in_document} pages; upgrade to Pro for full-document extraction."
            )
    else:
        page_indices = list(range(total_pages_in_document))
        warning = None

    pages_scanned = len(page_indices)
    total_tables_extracted = 0
    extracted_tables = []

    try:
        for page_index in page_indices:
            page = doc[page_index]

            try:
                detected_tables = list(page.find_tables(strategy="lines").tables)
            except Exception:
                continue

            unique_tables = {}
            for table in detected_tables:
                unique_tables[table_key(table)] = table

            for table_number, table in enumerate(unique_tables.values(), start=1):
                rows = table.extract() or []
                if not rows:
                    continue

                extracted_tables.append(
                    {
                        "page": page_index + 1,
                        "table_number_on_page": table_number,
                        "bbox": [round(v, 2) for v in table.bbox],
                        "rows": rows,
                    }
                )
                total_tables_extracted += 1
    finally:
        doc.close()

    return {
        "pages_scanned": pages_scanned,
        "total_tables_extracted": total_tables_extracted,
        "tables": extracted_tables,
        "warning": warning,
    }


@app.post("/webhook", include_in_schema=False)
async def stripe_webhook(request: Request):
    """
    Stripe webhook: on successful checkout, issue a new API key for the customer email.
    """
    raw_body = await request.body()
    try:
        payload = json.loads(raw_body.decode("utf-8"))
        event = stripe.Event.construct_from(payload, stripe.api_key)
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid webhook payload: {exc}") from exc

    if event.type == "checkout.session.completed":
        session = event.data.object
        customer_email = getattr(session, "customer_email", None)
        if not customer_email:
            details = getattr(session, "customer_details", None)
            if details is not None:
                customer_email = getattr(details, "email", None)

        new_api_key = secrets.token_hex(12)
        VALID_API_KEYS[new_api_key] = customer_email or "unknown"

        print(
            f"Stripe checkout completed: issued API key for {customer_email!r} "
            f"(key stored in VALID_API_KEYS)."
        )

        persist_api_key_from_webhook(new_api_key, customer_email or "unknown")

        send_api_key_email(customer_email, new_api_key)

    return {"received": True}


if __name__ == "__main__":
    uvicorn.run("engine:app", host="0.0.0.0", port=8000, reload=False)
