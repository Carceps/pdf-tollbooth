import fitz  # PyMuPDF
import uvicorn
from fastapi import FastAPI, File, HTTPException, Security, UploadFile
from fastapi.security import APIKeyHeader


app = FastAPI(
    title="Nexus Extract API",
    description="Enterprise-grade structured data extraction for financial and legal documents.",
    version="1.0.0",
    docs_url="/" 
)
API_KEY = "pay_me_123"
api_key_header = APIKeyHeader(name="x-api-key", auto_error=False)


def table_key(table):
    """
    Build a stable key from table bounds to deduplicate repeated detections.
    """
    x0, y0, x1, y1 = table.bbox
    return (round(x0, 1), round(y0, 1), round(x1, 1), round(y1, 1))


@app.get("/health")
def home():
    return {"status": "The engine is running!"}


@app.post("/extract")
async def extract(
    file: UploadFile = File(...),
    api_key: str | None = Security(api_key_header),
):
    """
    Accept a PDF upload, scan every page, and extract only strict vector-lined
    tables (strategy="lines"). Return extracted table data as JSON.
    """
    if api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    if file.content_type != "application/pdf":
        raise HTTPException(status_code=400, detail="Only PDF files are supported.")

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


if __name__ == "__main__":
    uvicorn.run("engine:app", host="0.0.0.0", port=8000, reload=False)

