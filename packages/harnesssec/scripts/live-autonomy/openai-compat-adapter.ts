/**
 * Minimal OpenAI-compatible chat Completions → DSH LlmAdapter stream.
 * Lives in experiments/ only — not Harn.x core.
 */
import type { GenerateOptions, LlmResolvedModelInfo, StreamChunk } from '@deepseek-ai/dsh-llm'
import { CallId, LlmAdapter } from '@deepseek-ai/dsh-llm'

export interface OpenAICompatConfig {
  provider: string
  model: string
  apiKey: string
  baseUrl?: string
}

function* textChunks(text: string): Generator<StreamChunk> {
  yield { type: 'block-start', index: 0, blockType: 'text' }
  yield { type: 'text-delta', index: 0, text }
  yield { type: 'block-end', index: 0, block: { type: 'text', text } }
}

function* toolChunks(id: string, name: string, args: string): Generator<StreamChunk> {
  const callId = CallId(id)
  yield { type: 'block-start', index: 0, blockType: 'tool-call' }
  yield { type: 'tool-call-delta', index: 0, id: callId, name, argumentsDelta: args }
  yield {
    type: 'block-end',
    index: 0,
    block: { type: 'tool-call', id: callId, name, arguments: args },
  }
}

export class OpenAICompatAdapter extends LlmAdapter {
  constructor(private readonly cfg: OpenAICompatConfig) {
    super()
  }

  override resolveModel(provider: string, model: string): Promise<LlmResolvedModelInfo> {
    return Promise.resolve({ provider, id: model, name: model })
  }

  async * stream(options: GenerateOptions): AsyncIterable<StreamChunk> {
    const base = (this.cfg.baseUrl ?? 'https://api.openai.com/v1').replace(/\/$/, '')
    const tools = (options.tools ?? []).map((t: any) => ({
      type: 'function',
      function: {
        name: t.name ?? t.function?.name,
        description: t.description ?? t.function?.description ?? '',
        parameters: t.parameters ?? t.function?.parameters ?? { type: 'object', properties: {} },
      },
    }))

    const messages: Array<Record<string, unknown>> = []
    if (options.system) {
      messages.push({ role: 'system', content: options.system })
    }
    for (const m of options.messages ?? []) {
      messages.push(m as Record<string, unknown>)
    }

    const res = await fetch(`${base}/chat/completions`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${this.cfg.apiKey}`,
      },
      body: JSON.stringify({
        model: this.cfg.model,
        messages,
        tools: tools.length ? tools : undefined,
        tool_choice: tools.length ? 'auto' : undefined,
      }),
    })

    if (!res.ok) {
      const body = await res.text()
      throw new Error(`OpenAI-compat HTTP ${res.status}: ${body.slice(0, 400)}`)
    }

    const json = await res.json() as any
    const choice = json.choices?.[0]?.message
    if (!choice) throw new Error('OpenAI-compat: empty choices')

    const toolCalls = choice.tool_calls ?? []
    if (toolCalls.length) {
      if (choice.content) yield* textChunks(String(choice.content))
      for (const tc of toolCalls) {
        const id = String(tc.id ?? `call_${Math.random().toString(16).slice(2)}`)
        const name = String(tc.function?.name ?? 'unknown')
        const args = String(tc.function?.arguments ?? '{}')
        yield* toolChunks(id, name, args)
      }
      yield { type: 'usage', usage: { inputTokens: json.usage?.prompt_tokens ?? 0, outputTokens: json.usage?.completion_tokens ?? 0 } }
      yield { type: 'finish', reason: { kind: 'tool-calls' } }
      return
    }

    const text = String(choice.content ?? '')
    yield* textChunks(text)
    yield { type: 'usage', usage: { inputTokens: json.usage?.prompt_tokens ?? 0, outputTokens: json.usage?.completion_tokens ?? 0 } }
    yield { type: 'finish', reason: { kind: 'stop' } }
  }
}
