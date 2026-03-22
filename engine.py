import json
import secrets
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import fitz  # PyMuPDF
import stripe
import uvicorn
from fastapi import FastAPI, Request, HTTPException, Depends, UploadFile, File, Security
from fastapi.responses import HTMLResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field


DATABASE_PATH = Path(__file__).resolve().parent / "nexus_api.db"


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
    Require a valid API key present in the api_keys table.
    Raises HTTP 401 Unauthorized if missing or not found in the database.
    """
    if not api_key:
        raise HTTPException(status_code=401, detail="Unauthorized")
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

    pages_scanned: int = Field(..., description="Total number of PDF pages processed.")
    total_tables_extracted: int = Field(
        ...,
        description="Count of distinct lined tables extracted across all pages.",
    )
    tables: list[ExtractTableItem] = Field(
        ...,
        description="Per-table payloads including row/column cell text.",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "pages_scanned": 3,
                "total_tables_extracted": 2,
                "tables": [
                    {
                        "page": 1,
                        "table_number_on_page": 1,
                        "bbox": [72.0, 120.5, 520.0, 400.0],
                        "rows": [
                            ["Account", "Balance", "Currency"],
                            ["Operating", "125000.00", "USD"],
                            ["Reserve", "45000.00", "USD"],
                        ],
                    },
                    {
                        "page": 2,
                        "table_number_on_page": 1,
                        "bbox": [50.0, 200.0, 540.0, 360.0],
                        "rows": [
                            ["Line item", "Amount"],
                            ["Subtotal", "170000.00"],
                        ],
                    },
                ],
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
        <title>Nexus Extract API</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: #111; color: #fff; margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; height: 100vh; text-align: center; }
            .container { max-width: 600px; padding: 40px; background: #222; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.5); border: 1px solid #333; }
            h1 { font-size: 2.5em; margin-bottom: 10px; background: linear-gradient(90deg, #00C9FF 0%, #92FE9D 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
            p { font-size: 1.1em; color: #aaa; margin-bottom: 30px; line-height: 1.5; }
            .btn { display: inline-block; padding: 15px 30px; font-size: 1.2em; font-weight: bold; color: #111; background: #00C9FF; text-decoration: none; border-radius: 8px; transition: 0.3s; }
            .btn:hover { background: #92FE9D; transform: translateY(-2px); }
            .docs-link { display: block; margin-top: 20px; color: #666; text-decoration: none; font-size: 0.9em; }
            .docs-link:hover { color: #fff; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Nexus Extract API</h1>
            <p>Enterprise-grade PDF table extraction. Convert messy, unstructured PDF documents into perfectly clean, machine-readable JSON instantly.</p>
            <a href="YOUR_STRIPE_LINK_HERE" class="btn">Get API Access - $49</a>
            <a href="/docs" class="docs-link">View API Documentation &rarr;</a>
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
        "Upload a PDF document. The engine scans **every page** and detects tables using "
        "PyMuPDF's strict **line-based** strategy (`strategy='lines'`), which requires "
        "explicit drawn vector borders. Borderless paragraphs, form fields, and whitespace-only "
        "layouts are ignored.\n\n"
        "The response lists each table with its page number, bounding box, and a **rows** matrix "
        "of cell strings (or nulls for empty cells). Authentication: send header `x-api-key` "
        "with a key registered for your account."
    ),
    responses={
        400: {"description": "Bad request — invalid file type or unreadable PDF."},
        401: {"description": "Unauthorized — missing or invalid API key."},
    },
)
async def extract(
    file: UploadFile = File(
        ...,
        description="PDF file to analyze (Content-Type must be application/pdf).",
    ),
    _api_key: str = Depends(verify_api_key),
):
    """
    Accept a PDF upload, scan every page, and extract only strict vector-lined
    tables (strategy="lines"). Return extracted table data as JSON.
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

    pages_scanned = len(doc)
    total_tables_extracted = 0
    extracted_tables = []

    try:
        # Iterate through every page so multi-page documents are fully processed.
        for page_index in range(pages_scanned):
            page = doc[page_index]

            # Strict line-based strategy: requires explicit drawn borders.
            # This ignores borderless paragraphs, floating fields, and whitespace guesses.
            try:
                detected_tables = list(page.find_tables(strategy="lines").tables)
            except Exception:
                # If detection fails on a page, skip that page and keep processing.
                continue

            # Remove duplicate detections on the same page using bounding boxes.
            unique_tables = {}
            for table in detected_tables:
                unique_tables[table_key(table)] = table

            # Extract each table as rows/columns and add it to the response payload.
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

    return {"received": True}


if __name__ == "__main__":
    uvicorn.run("engine:app", host="0.0.0.0", port=8000, reload=False)
