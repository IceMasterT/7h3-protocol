import {
  type ProtocolEnvelope,
  createEnvelope,
  signEnvelopeEd25519,
  verifyEnvelopeEd25519,
} from './protocol'

export interface QueueSignOptions {
  privateKey: string
  sender: string
  recipient?: string
  ttlMs?: number
  keyId?: string
}

export interface QueueVerifyOptions {
  publicKey: string
}

export type SignedEnvelope = ProtocolEnvelope

export interface QueueMessage<T> {
  envelope: SignedEnvelope
  payload: T
}

/**
 * Signs a payload for queue transit (Kafka/SQS/Pub-Sub/RabbitMQ).
 * Returns a JSON string: {"envelope": SignedEnvelope, "payload": T}
 * Default TTL is 1 hour (3 600 000 ms).
 */
export async function signQueueMessage<T>(
  payload: T,
  opts: QueueSignOptions,
): Promise<string> {
  const ttlMs = opts.ttlMs ?? 3_600_000
  const content = typeof payload === 'string' ? payload : JSON.stringify(payload)

  const envelope = createEnvelope({
    sender: opts.sender,
    recipient: opts.recipient,
    intent: 'TASK',
    content,
    ttlMs,
  })

  const signed = await signEnvelopeEd25519(envelope, opts.privateKey, opts.keyId)

  const message: QueueMessage<T> = { envelope: signed, payload }
  return JSON.stringify(message)
}

/**
 * Parses a queue message JSON string and verifies the envelope signature.
 * Throws if the message is malformed or the signature is invalid.
 */
export async function verifyQueueMessage<T>(
  message: string,
  opts: QueueVerifyOptions,
): Promise<{ payload: T; envelope: ProtocolEnvelope }> {
  let parsed: QueueMessage<T>
  try {
    parsed = JSON.parse(message) as QueueMessage<T>
  } catch {
    throw new Error('Queue message is not valid JSON')
  }

  if (!parsed.envelope || typeof parsed.envelope !== 'object') {
    throw new Error('Queue message missing envelope')
  }

  const valid = await verifyEnvelopeEd25519(parsed.envelope, opts.publicKey)
  if (!valid) {
    throw new Error('Queue message signature verification failed')
  }

  return { payload: parsed.payload, envelope: parsed.envelope }
}

/**
 * Verifies a batch of queue message strings.
 * Never throws — returns per-message success/failure objects.
 */
export async function verifyQueueBatch<T>(
  messages: string[],
  opts: QueueVerifyOptions,
): Promise<Array<{ ok: true; payload: T; envelope: ProtocolEnvelope } | { ok: false; raw: string; error: string }>> {
  return Promise.all(
    messages.map(async (raw) => {
      try {
        const { payload, envelope } = await verifyQueueMessage<T>(raw, opts)
        return { ok: true as const, payload, envelope }
      } catch (err) {
        return {
          ok: false as const,
          raw,
          error: err instanceof Error ? err.message : String(err),
        }
      }
    }),
  )
}
