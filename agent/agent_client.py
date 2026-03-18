import logging
from tools import ALL_TOOLS
from tools import nuclei, sqlmap, ffuf, recon, set_phish, cleanup, bettercap, zphisher, cyberstrike, read_log, payloads
from providers import get_provider


class AgentClient:

    def __init__(self, config: dict):
        self.provider = get_provider(config)
        self.raw_tools = ALL_TOOLS
        self.tools = self.provider.convert_tools(ALL_TOOLS)
        self.mapping = {
            "run_nuclei": nuclei.run,
            "run_sqlmap": sqlmap.run,
            "run_ffuf": ffuf.run,
            "run_recon": recon.run,
            "generate_phish_template": set_phish.run,
            "cleanup_temp": cleanup.run,
            "run_bettercap": bettercap.run,
            "generate_zphisher_template": zphisher.run,
            "run_cyberstrike": cyberstrike.run,
            "read_log": read_log.run,
            "run_payloads": payloads.run,
        }

    def think(self, messages: list, system_prompt: str) -> list:
        text_blocks, tool_calls = self.provider.call(messages, system_prompt, self.tools)

        new_messages = messages.copy()

        # Build assistant message (single block per turn)
        assistant_blocks = []
        for text in text_blocks:
            print("🤖 Phantom :", text)
            logging.info(f"Reasoning: {text[:300]}...")
            assistant_blocks.append({"type": "text", "text": text})

        for tc in tool_calls:
            assistant_blocks.append({
                "type": "tool_use",
                "id": tc["id"],
                "name": tc["name"],
                "input": tc["input"],
            })

        if assistant_blocks:
            new_messages.append({"role": "assistant", "content": assistant_blocks})

        # Execute tools — collect all results in a single user message
        if tool_calls:
            tool_results = []
            for tc in tool_calls:
                logging.info(f"🔧 Execution : {tc['name']}")
                tool_func = self.mapping.get(tc["name"])

                if tool_func:
                    try:
                        result = tool_func(**tc["input"])
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": tc["id"],
                            "content": str(result),
                        })
                    except Exception as e:
                        error_msg = f"Erreur {tc['name']}: {str(e)}"
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": tc["id"],
                            "content": error_msg,
                        })
                        logging.error(error_msg)
                else:
                    logging.warning(f"Tool inconnu : {tc['name']}")

            if tool_results:
                new_messages.append({"role": "user", "content": tool_results})

        return new_messages
