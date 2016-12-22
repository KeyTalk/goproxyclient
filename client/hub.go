// Copyright 2013 The Gorilla WebSocket Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package client

import (
	"fmt"
)

// hub maintains the set of active clients and broadcasts messages to the
// clients.
type Hub struct {
	// Registered clients.
	clients map[*connection]bool

	// Inbound messages from the clients.
	broadcast chan interface{}

	// Register requests from the clients.
	register chan *connection

	// Unregister requests from clients.
	unregister chan *connection
}

func newHub() *Hub {
	return &Hub{
		broadcast:  make(chan interface{}),
		register:   make(chan *connection),
		unregister: make(chan *connection),
		clients:    make(map[*connection]bool),
	}
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
		case message := <-h.broadcast:
			fmt.Println("Got message")
			for client := range h.clients {
				fmt.Println("sending message to cliient con")
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
		}
	}
}
