function completionsURL() {
  if (process.env.LLM_CHAT_COMPLETIONS_URL) {
    return process.env.LLM_CHAT_COMPLETIONS_URL;
  }

  const base=process.env.LLM_BASE_URL;
  if (!base) {
    throw new Error(
      "Set LLM_BASE_URL (or LLM_CHAT_COMPLETIONS_URL) and LLM_MODEL to run the real LLM tool-calling mode."
    );
  }

  const clean=base.replace(/\/+$/,"");
  return clean.endsWith("/v1")
    ? `${clean}/chat/completions`
    : `${clean}/v1/chat/completions`;
}

export async function chatCompletion({messages,tools}) {
  const model=process.env.LLM_MODEL;
  if (!model) {
    throw new Error("LLM_MODEL is required for real LLM tool-calling mode.");
  }

  const headers={"content-type":"application/json"};
  const apiKey=process.env.LLM_API_KEY;
  if (apiKey) headers.authorization=`Bearer ${apiKey}`;

  const response=await fetch(completionsURL(),{
    method:"POST",
    headers,
    body:JSON.stringify({
      model,
      messages,
      tools,
      tool_choice:"auto",
      temperature:0
    }),
    signal:AbortSignal.timeout(Number(process.env.LLM_TIMEOUT_MS || "30000"))
  });

  const text=await response.text();
  if (!response.ok) {
    throw new Error(`LLM HTTP ${response.status}: ${text.slice(0,1000)}`);
  }

  const body=JSON.parse(text);
  const message=body?.choices?.[0]?.message;
  if (!message) {
    throw new Error("OpenAI-compatible response did not contain choices[0].message");
  }
  return message;
}
