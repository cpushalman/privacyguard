import { io } from 'socket.io-client'

class SocketService {
  constructor() {
    this.socket = null
    this.isConnected = false
    this.reconnectAttempts = 0
    this.maxReconnectAttempts = 5
    this.baseUrl = import.meta.env?.VITE_API_URL || 'http://localhost:5000'
  }

  connect() {
    if (this.socket && this.isConnected) {
      return Promise.resolve()
    }

    return new Promise((resolve, reject) => {
      this.socket = io(`${this.baseUrl}/scan`, {
        transports: ['websocket', 'polling'],
        timeout: 10000,
        reconnection: true,
        reconnectionAttempts: this.maxReconnectAttempts,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000
      })

      this.socket.on('connect', () => {
        console.log('Connected to WebSocket server')
        this.isConnected = true
        this.reconnectAttempts = 0
        resolve()
      })

      this.socket.on('connect_error', (error) => {
        console.error('WebSocket connection error:', error)
        this.isConnected = false
        reject(error)
      })

      this.socket.on('disconnect', (reason) => {
        console.log('Disconnected from WebSocket server:', reason)
        this.isConnected = false
      })

      this.socket.on('reconnect', (attemptNumber) => {
        console.log(`Reconnected after ${attemptNumber} attempts`)
        this.isConnected = true
      })

      this.socket.on('reconnect_error', (error) => {
        console.error('Reconnection failed:', error)
        this.reconnectAttempts++
      })
    })
  }

  disconnect() {
    if (this.socket) {
      this.socket.disconnect()
      this.socket = null
      this.isConnected = false
    }
  }

  // Network scanning events
  onNetworkUpdate(callback) {
    if (this.socket) {
      this.socket.on('network_update', callback)
    }
  }

  onScanStatus(callback) {
    if (this.socket) {
      this.socket.on('scan_status', callback)
    }
  }

  onScanError(callback) {
    if (this.socket) {
      this.socket.on('scan_error', callback)
    }
  }

  // Emit events to server
  startRealtimeScan() {
    if (this.socket && this.isConnected) {
      this.socket.emit('start_scan')
    }
  }

  stopRealtimeScan() {
    if (this.socket && this.isConnected) {
      this.socket.emit('stop_scan')
    }
  }

  requestSingleScan() {
    if (this.socket && this.isConnected) {
      this.socket.emit('request_scan')
    }
  }

  // Remove event listeners
  removeNetworkUpdateListener(callback) {
    if (this.socket) {
      this.socket.off('network_update', callback)
    }
  }

  removeScanStatusListener(callback) {
    if (this.socket) {
      this.socket.off('scan_status', callback)
    }
  }

  removeScanErrorListener(callback) {
    if (this.socket) {
      this.socket.off('scan_error', callback)
    }
  }

  // Connection status
  getConnectionStatus() {
    return {
      connected: this.isConnected,
      socketId: this.socket?.id
    }
  }
}

// Export singleton instance
const socketService = new SocketService()
export default socketService
