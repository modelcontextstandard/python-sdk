from fastapi import FastAPI, Query
from pydantic import BaseModel

app = FastAPI(
    title="Fibonacci API",
    description="Returns 2x Fibonacci(n) for quick MCS concept checks.",
    version="1.0.0",
)


class FibonacciResponse(BaseModel):
    result: int


def fib(n: int) -> int:
    if n < 2:
        return 1
    a, b = 1, 1
    for _ in range(n - 1):
        a, b = b, a + b
    return b


@app.get(
    "/tools/fibonacci",
    response_model=FibonacciResponse,
    tags=["Tools"],
    summary="Calculate 2x Fibonacci(n)",
)
async def get_fibonacci(
    n: int = Query(..., ge=0, description="Position in the Fibonacci sequence"),
):
    return {"result": 2 * fib(n)}


def main() -> None:
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8001)


if __name__ == "__main__":
    main()
