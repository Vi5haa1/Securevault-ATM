import { useState, useEffect, useRef, useCallback } from 'react';

type MessageHandler = (data: any) => void;

class RealtimeSocketService {
  private socket: WebSocket | null = null;
  private listeners: Map<string, Set<MessageHandler>> = new Map();
  private reconnectTimeout: any = null;
  private pingInterval: any = null;
  private isConnecting = false;
  private shouldReconnect = true;

  constructor() {
    this.connect();
  }

  public connect() {
    if (this.socket && (this.socket.readyState === WebSocket.OPEN || this.socket.readyState === WebSocket.CONNECTING)) {
      return;
    }
    if (this.isConnecting) return;

    this.isConnecting = true;
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // In dev, Vite proxies /ws to ws://127.0.0.1:8000; in prod, nginx proxies /ws
    const wsUrl = `${protocol}//${window.location.host}/ws`;

    try {
      this.socket = new WebSocket(wsUrl);

      this.socket.onopen = () => {
        this.isConnecting = false;
        this.dispatch('connection_status', { connected: true });
        this.startHeartbeat();
      };

      this.socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type) {
            this.dispatch(data.type, data);
          }
          this.dispatch('*', data);
        } catch {
          // Non-JSON message
        }
      };

      this.socket.onclose = () => {
        this.isConnecting = false;
        this.stopHeartbeat();
        this.dispatch('connection_status', { connected: false });
        if (this.shouldReconnect) {
          clearTimeout(this.reconnectTimeout);
          this.reconnectTimeout = setTimeout(() => this.connect(), 3000);
        }
      };

      this.socket.onerror = () => {
        if (this.socket) {
          this.socket.close();
        }
      };
    } catch (e) {
      this.isConnecting = false;
      if (this.shouldReconnect) {
        clearTimeout(this.reconnectTimeout);
        this.reconnectTimeout = setTimeout(() => this.connect(), 4000);
      }
    }
  }

  private startHeartbeat() {
    this.stopHeartbeat();
    this.pingInterval = setInterval(() => {
      if (this.socket && this.socket.readyState === WebSocket.OPEN) {
        this.socket.send('ping');
      }
    }, 15000);
  }

  private stopHeartbeat() {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }

  public subscribe(eventType: string, handler: MessageHandler): () => void {
    if (!this.listeners.has(eventType)) {
      this.listeners.set(eventType, new Set());
    }
    this.listeners.get(eventType)!.add(handler);

    return () => {
      const handlers = this.listeners.get(eventType);
      if (handlers) {
        handlers.delete(handler);
      }
    };
  }

  private dispatch(eventType: string, data: any) {
    const handlers = this.listeners.get(eventType);
    if (handlers) {
      handlers.forEach((h) => {
        try {
          h(data);
        } catch (e) {
          console.error('Error in socket handler:', e);
        }
      });
    }
  }

  public isConnected(): boolean {
    return this.socket !== null && this.socket.readyState === WebSocket.OPEN;
  }
}

export const realtimeSocket = new RealtimeSocketService();

export function useRealtimeWs() {
  const [isConnected, setIsConnected] = useState<boolean>(realtimeSocket.isConnected());
  const [lastTelemetry, setLastTelemetry] = useState<any[] | null>(null);
  const [lastAlert, setLastAlert] = useState<any | null>(null);
  const [lastEvent, setLastEvent] = useState<any | null>(null);

  useEffect(() => {
    const unsubStatus = realtimeSocket.subscribe('connection_status', (data) => {
      setIsConnected(data.connected);
    });

    const unsubTelemetry = realtimeSocket.subscribe('ATM_TELEMETRY_UPDATE', (data) => {
      if (data.atms) {
        setLastTelemetry(data.atms);
      }
    });

    const unsubAlert = realtimeSocket.subscribe('SECURITY_ALERT', (data) => {
      setLastAlert(data);
    });

    const unsubPipeline = realtimeSocket.subscribe('PIPELINE_EVENT', (data) => {
      setLastEvent(data.event || data);
    });

    // Initial check
    setIsConnected(realtimeSocket.isConnected());

    return () => {
      unsubStatus();
      unsubTelemetry();
      unsubAlert();
      unsubPipeline();
    };
  }, []);

  return {
    isConnected,
    lastTelemetry,
    lastAlert,
    lastEvent,
  };
}
