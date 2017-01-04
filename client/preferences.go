package client

import (
	"encoding/json"
	"os"
	"sync"
)

type Preferences struct {
	path  string
	items map[string]interface{}
	m     sync.Mutex
}

func (p Preferences) Get(key string) (interface{}, bool) {
	p.m.Lock()
	defer p.m.Unlock()

	v, ok := p.items[key]
	return v, ok
}

func (p Preferences) Load() {
	p.m.Lock()
	defer p.m.Unlock()

	if f, err := os.Open(p.path); err != nil {
		log.Errorf("Error reading preferences: %s", err)
	} else if err := json.NewDecoder(f).Decode(&p.items); err != nil {
		log.Errorf("Error reading preferences: %s", err)
	} else {
		defer f.Close()
	}
}

func (p Preferences) Sync() {
	p.m.Lock()
	defer p.m.Unlock()

	if f, err := os.OpenFile(p.path, os.O_CREATE|os.O_WRONLY, 0600); err != nil {
		log.Errorf("Error writing preferences: %s", err)
	} else if err := json.NewEncoder(f).Encode(&p.items); err != nil {
		log.Errorf("Error writing preferences: %s", err)
	} else {
		defer f.Close()
	}
}

func (p Preferences) Set(key string, val interface{}) {
	p.m.Lock()
	defer p.m.Unlock()

	p.items[key] = val
}
