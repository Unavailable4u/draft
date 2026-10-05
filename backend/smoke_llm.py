import os
from openai import OpenAI

c = OpenAI(base_url=os.environ["LLM_BASE_URL"], api_key=os.environ["LLM_API_KEY"])
tools = [{"type": "function", "function": {
    "name": "run_shell", "description": "Run a shell command in the sandbox",
    "parameters": {"type": "object",
                   "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]}}}]
r = c.chat.completions.create(
    model=os.environ["LLM_MODEL"],
    messages=[{"role": "user", "content": "List the files in the current directory."}],
    tools=tools, tool_choice="auto")
m = r.choices[0].message
print(m.tool_calls or m.content)
print(r.usage)
