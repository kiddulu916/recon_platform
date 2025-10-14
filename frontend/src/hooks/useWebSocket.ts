import { useEffect, useCallback, useState } from 'react';
import wsService from '../services/websocket';
import type { WebSocketMessageType } from '../types';

interface UseWebSocketOptions {
  domainId?: number;
  autoConnect?: boolean;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: any) => void;
}

interface UseWebSocketReturn {
  isConnected: boolean;
  connect: () => void;
  disconnect: () => void;
  subscribe: <T = any>(type: WebSocketMessageType, handler: (data: T) => void) => () => void;
}

/**
 * Custom hook for managing WebSocket connections
 * Automatically handles connection/disconnection on mount/unmount
 * Provides simple API for subscribing to WebSocket events
 *
 * @example
 * const { isConnected, subscribe } = useWebSocket({
 *   domainId: 1,
 *   autoConnect: true
 * });
 *
 * useEffect(() => {
 *   const unsubscribe = subscribe('scan_progress', (data) => {
 *     console.log('Scan progress:', data);
 *   });
 *   return unsubscribe;
 * }, [subscribe]);
 */
export function useWebSocket(options: UseWebSocketOptions = {}): UseWebSocketReturn {
  const {
    domainId,
    autoConnect = true,
    onConnect,
    onDisconnect,
    onError
  } = options;

  const [isConnected, setIsConnected] = useState(false);

  const connect = useCallback(() => {
    wsService.connect(domainId);
  }, [domainId]);

  const disconnect = useCallback(() => {
    wsService.disconnect();
  }, []);

  const subscribe = useCallback(<T = any>(
    type: WebSocketMessageType,
    handler: (data: T) => void
  ): (() => void) => {
    wsService.on(type, handler);

    // Return unsubscribe function
    return () => {
      wsService.off(type, handler);
    };
  }, []);

  // Handle connection status
  useEffect(() => {
    const handleConnectionEstablished = () => {
      setIsConnected(true);
      onConnect?.();
    };

    const handleError = (error: any) => {
      setIsConnected(false);
      onError?.(error);
    };

    subscribe('connection_established', handleConnectionEstablished);
    subscribe('error', handleError);

    return () => {
      wsService.off('connection_established', handleConnectionEstablished);
      wsService.off('error', handleError);
    };
  }, [onConnect, onError, subscribe]);

  // Auto-connect on mount, disconnect on unmount
  useEffect(() => {
    if (autoConnect) {
      connect();
    }

    return () => {
      disconnect();
      setIsConnected(false);
      onDisconnect?.();
    };
  }, [autoConnect, connect, disconnect, onDisconnect]);

  // Check connection status periodically
  useEffect(() => {
    const interval = setInterval(() => {
      const connected = wsService.isConnected();
      setIsConnected(connected);
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  return {
    isConnected,
    connect,
    disconnect,
    subscribe
  };
}
