const state={
  httpGetRuns:0,
  webhookRuns:0,
  shellRuns:0
};

function bodyPreview(text,max=500) {
  return text.length<=max ? text : `${text.slice(0,max)}…`;
}

export function toolState() {
  return {...state};
}

export const toolDefinitions=[
  {
    type:"function",
    function:{
      name:"http_get",
      description:"Fetch a public HTTP(S) URL and return a short response preview.",
      parameters:{
        type:"object",
        properties:{url:{type:"string"}},
        required:["url"],
        additionalProperties:false
      }
    }
  },
  {
    type:"function",
    function:{
      name:"shell_exec",
      description:"Request a shell command. This example keeps actual shell execution disabled; AIVF CCS must deny dangerous command patterns before the tool body is reached.",
      parameters:{
        type:"object",
        properties:{command:{type:"string"}},
        required:["command"],
        additionalProperties:false
      }
    }
  },
  {
    type:"function",
    function:{
      name:"send_webhook",
      description:"POST JSON to a public webhook URL. Authorization-like material in an outbound request should be denied by AIVF CCS.",
      parameters:{
        type:"object",
        properties:{
          url:{type:"string"},
          authorization:{type:"string"},
          body:{type:"object"}
        },
        required:["url","body"],
        additionalProperties:false
      }
    }
  }
];

export const tools={
  async http_get({url}) {
    state.httpGetRuns += 1;

    if ((process.env.AIVF_HTTP_MODE || "real").toLowerCase()==="stub") {
      return {
        status:200,
        content_type:"text/plain",
        body_preview:`stubbed HTTP response for ${url}`
      };
    }

    const response=await fetch(url,{
      method:"GET",
      redirect:"follow",
      signal:AbortSignal.timeout(Number(process.env.AIVF_HTTP_TIMEOUT_MS || "5000"))
    });
    const text=await response.text();
    return {
      status:response.status,
      content_type:response.headers.get("content-type"),
      body_preview:bodyPreview(text)
    };
  },

  async shell_exec({command}) {
    state.shellRuns += 1;
    throw new Error(
      `shell execution is intentionally disabled in this public example; requested: ${command}`
    );
  },

  async send_webhook({url,authorization,body}) {
    state.webhookRuns += 1;

    if ((process.env.AIVF_HTTP_MODE || "real").toLowerCase()==="stub") {
      return {
        status:200,
        body_preview:`stubbed webhook response for ${url}`
      };
    }

    const headers={"content-type":"application/json"};
    if (authorization) headers.authorization=authorization;

    const response=await fetch(url,{
      method:"POST",
      headers,
      body:JSON.stringify(body),
      signal:AbortSignal.timeout(Number(process.env.AIVF_HTTP_TIMEOUT_MS || "5000"))
    });
    const text=await response.text();
    return {
      status:response.status,
      body_preview:bodyPreview(text)
    };
  }
};
