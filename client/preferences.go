package client

import (
	"encoding/json"
	"os"
)

type Preferences struct {
	path  string
	items map[string]string
}

func (p Preferences) Get(key string) string {
	p.load()
	return p.items[key]
}

func (p Preferences) load() {
	log.Debugf("Reading preferences from: %s", p.path)
	if f, err := os.Open(p.path); err != nil {
		log.Errorf("Error reading preferences: %s", err)
	} else if err := json.NewDecoder(f).Decode(&p.items); err != nil {
		log.Errorf("Error reading preferences: %s", err)
	} else {
		defer f.Close()

		log.Errorf("Prefs loaded %s %#v", p.path, p.items)
	}
}

func (p Preferences) save() {
	log.Debugf("Writing preferences to: %s", p.path)
	if f, err := os.OpenFile(p.path, os.O_CREATE|os.O_WRONLY, 0600); err != nil {
		log.Errorf("Error writing preferences: %s", err)
	} else if err := json.NewEncoder(f).Encode(&p.items); err != nil {
		log.Errorf("Error writing preferences: %s", err)
	} else {
		defer f.Close()

		log.Errorf("Prefs written %s %#v", p.path, p.items)
	}
}

func (p Preferences) Set(key, val string) {
	p.load()
	defer p.save()

	p.items[key] = val
}
