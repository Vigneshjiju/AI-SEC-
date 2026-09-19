/**
 * MCP-Sentinel: Sentinel Event Bus
 * Simple pub/sub for internal security events.
 */

import type { SecurityEvent, SecurityEventType } from "./types.js";

export type EventHandler = (event: SecurityEvent) => void;

export class SentinelEventBus {
  private handlers: Map<SecurityEventType | "*", EventHandler[]> = new Map();
  private eventLog: SecurityEvent[] = [];
  private maxLogSize: number;

  constructor(maxLogSize = 10000) {
    this.maxLogSize = maxLogSize;
  }

  on(type: SecurityEventType | "*", handler: EventHandler): void {
    const list = this.handlers.get(type) ?? [];
    list.push(handler);
    this.handlers.set(type, list);
  }

  off(type: SecurityEventType | "*", handler: EventHandler): void {
    const list = this.handlers.get(type);
    if (!list) return;
    const idx = list.indexOf(handler);
    if (idx >= 0) list.splice(idx, 1);
  }

  emit(event: SecurityEvent): void {
    this.eventLog.push(event);
    if (this.eventLog.length > this.maxLogSize) {
      this.eventLog = this.eventLog.slice(-this.maxLogSize);
    }

    const specific = this.handlers.get(event.type) ?? [];
    const wildcard = this.handlers.get("*") ?? [];
    for (const handler of [...specific, ...wildcard]) {
      try {
        handler(event);
      } catch (err) {
        process.stderr.write(`[sentinel] Event handler error for ${event.type}: ${err}\n`);
      }
    }
  }

  getEvents(limit = 100, type?: SecurityEventType): SecurityEvent[] {
    let events = this.eventLog;
    if (type) {
      events = events.filter(e => e.type === type);
    }
    return events.slice(-limit);
  }

  getEventsSince(since: string): SecurityEvent[] {
    return this.eventLog.filter(e => e.timestamp >= since);
  }

  clear(): void {
    this.eventLog = [];
  }
}
