"""MCS REST API chat client using the RestOrchestrator.

Connects to a single OpenAPI endpoint, discovers its tools, and provides
an interactive chat loop with tool execution.

Usage:
    python chat.py [--url URL] [--model MODEL]

Requires:
    pip install mcs-orchestrator-rest litellm python-dotenv
    export OPENAI_API_KEY=sk-...
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, List

from dotenv import load_dotenv
from litellm import completion

from mcs.driver.core import MCSDriver
from mcs.orchestrator.rest import RestOrchestrator

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
    force=True,
)
logging.getLogger("LiteLLM").setLevel(logging.WARNING)

DEFAULT_URL = "https://mcs-quickstart.coolify.alsdienst.de/openapi.json"


class ChatSession:
    def __init__(self, driver: MCSDriver, model: str = "gpt-4o") -> None:
        self.mcs_driver = driver
        self.model = model

    async def _extract_llm_response(self, messages: List[Dict[str, str]]) -> str:
        llm_response = completion(model=self.model, messages=messages)
        return llm_response.choices[0].message.content  # type: ignore[union-attr]

    async def start(self) -> None:
        system_message = self.mcs_driver.get_driver_system_message()
        logging.info("System message:\n%s", system_message)
        messages: list[dict] = [{"role": "system", "content": system_message}]

        while True:
            try:
                user_input = input("You: ").strip()
                if user_input.lower() in ("quit", "exit", "q"):
                    logging.info("Exiting...")
                    break

                messages.append({"role": "user", "content": user_input})
                llm_response = await self._extract_llm_response(messages)
                logging.info("Assistant: %s", llm_response)

                response = self.mcs_driver.process_llm_response(llm_response)

                if response.messages:
                    messages.extend(response.messages)

                if response.call_executed:
                    final_response = await self._extract_llm_response(messages)
                    logging.info("Final response: %s", final_response)
                    messages.append({"role": "assistant", "content": final_response})
                elif not response.call_failed:
                    messages.append({"role": "assistant", "content": llm_response})

            except KeyboardInterrupt:
                logging.info("Exiting...")
                break


async def main() -> None:
    load_dotenv()

    import argparse
    p = argparse.ArgumentParser(description="MCS REST API chat client")
    p.add_argument("--url", default=DEFAULT_URL, help="OpenAPI spec URL")
    p.add_argument("--model", default="gpt-4o", help="LiteLLM model identifier")
    args = p.parse_args()

    orchestrator = RestOrchestrator()
    orchestrator.add_connection(args.url, label="api")
    print("Tools:", [t.name for t in orchestrator.list_tools()])

    chat_session = ChatSession(orchestrator, model=args.model)
    await chat_session.start()


if __name__ == "__main__":
    asyncio.run(main())
