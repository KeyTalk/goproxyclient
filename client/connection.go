package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"net/http"
	"time"
)

const (
	// Time allowed to write a message to the peer.
	writeWait = 10 * time.Second

	// Time allowed to read the next pong message from the peer.
	pongWait = 60 * time.Second

	// Send pings to peer with this period. Must be less than pongWait.
	pingPeriod = 1 * time.Second

	// Maximum message size allowed from peer.
	maxMessageSize = 512
)

type connection struct {
	ws     *websocket.Conn
	send   chan interface{}
	b      int
	client *Client
}

// write writes a message with the given message type and payload.
func (c *connection) write(mt int, payload []byte) error {
	c.ws.SetWriteDeadline(time.Now().Add(writeWait))
	return c.ws.WriteMessage(mt, payload)
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func (c *connection) readPump() {
	defer func() {
		c.client.hub.unregister <- c
		c.ws.Close()
	}()

	c.ws.SetReadLimit(maxMessageSize)
	c.ws.SetReadDeadline(time.Now().Add(pongWait))
	c.ws.SetPongHandler(func(string) error {
		c.ws.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := c.ws.ReadMessage()
		if err == nil {
		} else if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway) {
			log.Errorf("Connection closed unexpectedly: %s", err)
			continue
		}

		v := map[string]interface{}{}
		if err := json.NewDecoder(bytes.NewBuffer(message)).Decode(&v); err != nil {
			log.Errorf("Error decoding message: %s", err)
			continue
		}

		if v["type"] == "reload" {
			c.client.reloadRCCDs()
		} else if v["type"] == "delete-certificate" {
			c.client.deleteCertificate()
		} else if v["type"] == "retrieve-rccds" {
			rccds := []string{}
			for path := range c.client.rccds {
				rccds = append(rccds, path)
			}

			c.send <- map[string]interface{}{"type": "receive-rccds", "items": rccds}
		} else if v["type"] == "retrieve-service-uris" {
			services := []string{}
			for _, rccd := range c.client.rccds {
				for _, provider := range rccd.Providers {
					for _, service := range provider.Services {
						serviceURI := service.Uri

						if v, ok := c.client.Preferences.Get(fmt.Sprintf("%s/%s/service-uris", provider.Name, service.Name)); !ok {
						} else if serviceURIs, ok := v.([]string); ok {
							serviceURI = serviceURIs[0]
						} else if serviceURIs, ok := v.([]interface{}); ok {
							serviceURI = serviceURIs[0].(string)
						}

						services = append(services, serviceURI)
					}
				}
			}

			c.send <- map[string]interface{}{"type": "receive-service-uris", "services": services}
		}
	}
}

// writePump pumps messages from the hub to the websocket connection.
func (c *connection) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.ws.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				c.write(websocket.CloseMessage, []byte{})
				return
			}

			buff := new(bytes.Buffer)
			if err := json.NewEncoder(buff).Encode(message); err != nil {
				log.Error(err.Error())
				return
			} else if err := c.write(websocket.BinaryMessage, buff.Bytes()); err != nil {
				log.Error(err.Error())
				return
			}
		case <-ticker.C:
			if err := c.write(websocket.PingMessage, []byte{}); err != nil {
				log.Error("%#v", err.Error())
				return
			}
		}
	}
}
