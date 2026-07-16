export interface AsyncPipelineQueue<T> {
  push(item: T): void
  take(signal?: AbortSignal): Promise<T>
  clear(): void
  close(): void
  size(): number
  droppedCount(): number
}

export class LatestFrameQueue<T> implements AsyncPipelineQueue<T> {
  private items: T[] = []
  private waiters: Array<{ resolve: (item: T) => void; reject: (error: Error) => void }> = []
  private dropped = 0
  private closed = false

  constructor(private readonly capacity = 2) {
    if (capacity < 1) throw new Error('LatestFrameQueue capacity must be at least 1')
  }

  push(item: T) {
    if (this.closed) return
    const waiter = this.waiters.shift()
    if (waiter) {
      waiter.resolve(item)
      return
    }
    this.items.push(item)
    while (this.items.length > this.capacity) {
      this.items.shift()
      this.dropped += 1
    }
  }

  take(signal?: AbortSignal): Promise<T> {
    if (this.items.length) return Promise.resolve(this.items.pop() as T)
    if (this.closed) return Promise.reject(new Error('LatestFrameQueue is closed'))
    return new Promise<T>((resolve, reject) => {
      const waiter = { resolve, reject }
      const abort = () => {
        this.waiters = this.waiters.filter(item => item !== waiter)
        reject(new DOMException('Queue take cancelled', 'AbortError') as unknown as Error)
      }
      if (signal?.aborted) return abort()
      signal?.addEventListener('abort', abort, { once: true })
      this.waiters.push(waiter)
    })
  }

  clear() {
    this.dropped += this.items.length
    this.items = []
  }

  close() {
    this.closed = true
    this.items = []
    this.waiters.splice(0).forEach(waiter => waiter.reject(new Error('LatestFrameQueue is closed')))
  }

  size() {
    return this.items.length
  }

  droppedCount() {
    return this.dropped
  }
}
