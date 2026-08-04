# CSV Analysis Example

Interactive chat client that uses the **MCS CSV driver** (`mcs-driver-csv`)
to analyse local CSV files via natural language.

## What it shows

- How to instantiate a driver with `CsvDriver(base_dir="...")`
- The full tool-call loop: LLM → `process_llm_response()` → `execute_tool()` → LLM
- Non-streaming vs. streaming -- in streaming the client feeds each chunk into an
  `LLMStreamBuffer` and hands the buffer to the driver, which holds a forming
  tool call back so its JSON is never displayed

## Prerequisites

```bash
pip install mcs-driver-csv litellm rich python-dotenv
export OPENAI_API_KEY=sk-...
```

## Quick start

```bash
# Non-streaming (simplest):
python chat.py --debug

# Streaming:
python chat.py --stream --debug
```

## Sample data

- `data/sales.csv` — 5 orders with region, product, and amount
- `data2/inventory.csv` — 5 SKUs with warehouse, product, and quantity

Try: *"Which region has the highest total sales?"* or *"List all CSV files"*.
