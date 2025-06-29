import asyncio
import logging

from typing import Dict, List
from dotenv import load_dotenv

from mcs.drivers.core import MCSDriver, DriverMeta
from mcs.drivers.rest_http import RestHttpDriver

from litellm import completion

# Configure logging
logging.basicConfig(
        level=logging.INFO, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s", force=True
    )
logging.getLogger("LiteLLM").setLevel(logging.WARNING)

class ChatSession:
    def __init__(self, driver: MCSDriver) -> None:
        self.mcs_driver: MCSDriver = driver

    async def _extract_llm_response(self, model: str = "gpt-4o", messages: List[Dict[str, str]] = None,
                                    response_format: Dict[str, str] = None) \
            -> str:
        llm_response = completion(model=model, messages=messages, response_format=response_format)
        print(llm_response)
        llm_response = llm_response.choices[0].message.content

        return llm_response

    async def start(self) -> None:
        try:
            system_message = self.mcs_driver.get_driver_system_message()
            logging.info(f"\nSystem message:\n{system_message}\n")
            messages = [{"role": "system", "content": system_message}]

            while True:
                try:
                    user_input = input("You: ").strip().lower()
                    if user_input in ["quit", "exit"]:
                        logging.info("\nExiting...")
                        break

                    messages.append({"role": "user", "content": user_input})

                    llm_response = await self._extract_llm_response(messages=messages)
                    logging.info("\nAssistant: %s", llm_response)

                    result = self.mcs_driver.process_llm_response(llm_response)

                    if result != llm_response:
                        messages.append({"role": "assistant", "content": llm_response})
                        messages.append({"role": "system", "content": result})

                        final_response = await self._extract_llm_response(messages=messages)
                        logging.info("\nFinal response: %s", final_response)
                        messages.append(
                            {"role": "assistant", "content": final_response}
                        )
                    else:
                        messages.append({"role": "assistant", "content": llm_response})

                except KeyboardInterrupt:
                    logging.info("\nExiting...")
                    break
        except Exception as e:
            print(f"An error occurred: {e}")
            # Handle the exception as needed, e.g., logging or retrying


async def main() -> None:
    load_dotenv()

    # Optional Autostart and getting the URLs

    # Only one url is implemented right now, need to do some magic if we want to support multiple urls
    function_spec_urls = ['https://mcs-quickstart.coolify.alsdienst.de/openapi.json']
    http_driver = RestHttpDriver(function_spec_urls)

    chat_session = ChatSession(http_driver)
    await chat_session.start()


if __name__ == "__main__":
    asyncio.run(main())