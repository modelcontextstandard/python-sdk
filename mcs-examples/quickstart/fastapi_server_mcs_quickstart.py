import json

from fastapi import FastAPI, Query
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse

app = FastAPI(
    title="Fibonacci API",
    description="HTML OpenAPI quickstart endpoint for browser-based LLM checks.",
    version="1.0.0",
)


def fibonacci(n: int) -> int:
    if n <= 1:
        return max(0, n)
    a, b = 0, 1
    for _ in range(2, n + 1):
        a, b = b, a + b
    return b


@app.get("/openapi-html", response_class=HTMLResponse)
async def openapi_as_html() -> HTMLResponse:
    spec = get_openapi(title=app.title, version=app.version, routes=app.routes)
    spec_json = json.dumps(spec, indent=2, ensure_ascii=False)
    html = f"""
    <html>
      <head><title>OpenAPI Spec</title></head>
      <body>
        <h1>OpenAPI Spec</h1>
        <pre>{spec_json}</pre>
      </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.get("/tools/fibonacci", response_class=HTMLResponse, tags=["Tools"])
async def get_fibonacci_html(
    n: int = Query(..., ge=0, description="Position in the Fibonacci sequence"),
) -> HTMLResponse:
    result = 2 * fibonacci(n)
    html = f"<html><body><h1>Result: {result}</h1></body></html>"
    return HTMLResponse(content=html, status_code=200)


def main() -> None:
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)


if __name__ == "__main__":
    main()
