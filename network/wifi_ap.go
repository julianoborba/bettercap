package network

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/evilsocket/islazy/data"
)

type AccessPoint struct {
	*Station
	sync.RWMutex

	aliases         *data.UnsortedKV
	clients         map[string]*Station
	withKeyMaterial bool
}

type apJSON struct {
	*Station

	Clients   []*Station `json:"clients"`
	Handshake bool       `json:"handshake"`
}

func NewAccessPoint(essid, bssid string, frequency int, rssi int8, aliases *data.UnsortedKV) *AccessPoint {
	return &AccessPoint{
		Station: NewStation(essid, bssid, frequency, rssi),
		aliases: aliases,
		clients: make(map[string]*Station),
	}
}

func CopyMap(original map[string]string) map[string]string {
	copy := make(map[string]string, len(original))
	for k, v := range original {
		copy[k] = v
	}
	return copy
}

func (ap *AccessPoint) BuildDoc() apJSON {
	ap.RLock()
	defer ap.RUnlock()

	clients := make([]*Station, 0, len(ap.clients))
	for _, client := range ap.clients {
		client.WPS = CopyMap(client.WPS)
		clients = append(clients, client)
	}

	station := ap.Station
	station.WPS = CopyMap(ap.WPS)

	handshake := ap.withKeyMaterial

	return apJSON{
		Station:   station,
		Clients:   clients,
		Handshake: handshake,
	}
}

func (ap *AccessPoint) MarshalJSON() ([]byte, error) {
	jsonData, err := json.Marshal(ap.BuildDoc())
	if err != nil {
		fmt.Printf("error while serializing the access point struct: %s\n", err)
		return nil, err
	}
	return jsonData, nil
}

func (ap *AccessPoint) Get(bssid string) (*Station, bool) {
	ap.RLock()
	defer ap.RUnlock()

	bssid = NormalizeMac(bssid)
	if s, found := ap.clients[bssid]; found {
		return s, true
	}
	return nil, false
}

func (ap *AccessPoint) RemoveClient(mac string) {
	ap.Lock()
	defer ap.Unlock()

	bssid := NormalizeMac(mac)
	delete(ap.clients, bssid)
}

func (ap *AccessPoint) AddClientIfNew(bssid string, frequency int, rssi int8) (*Station, bool) {
	ap.Lock()
	defer ap.Unlock()

	bssid = NormalizeMac(bssid)
	alias := ap.aliases.GetOr(bssid, "")

	if s, found := ap.clients[bssid]; found {
		// update
		s.Frequency = frequency
		s.RSSI = rssi
		s.LastSeen = time.Now()

		if alias != "" {
			s.Alias = alias
		}

		return s, false
	}

	s := NewStation("", bssid, frequency, rssi)
	s.Alias = alias
	ap.clients[bssid] = s

	return s, true
}

func (ap *AccessPoint) NumClients() int {
	ap.RLock()
	defer ap.RUnlock()
	return len(ap.clients)
}

func (ap *AccessPoint) Clients() (list []*Station) {
	ap.RLock()
	defer ap.RUnlock()

	list = make([]*Station, 0, len(ap.clients))
	for _, c := range ap.clients {
		list = append(list, c)
	}
	return
}

func (ap *AccessPoint) EachClient(cb func(mac string, station *Station)) {
	ap.Lock()
	defer ap.Unlock()

	for m, station := range ap.clients {
		cb(m, station)
	}
}

func (ap *AccessPoint) WithKeyMaterial(state bool) {
	ap.Lock()
	defer ap.Unlock()

	ap.withKeyMaterial = state
}

func (ap *AccessPoint) HasKeyMaterial() bool {
	ap.RLock()
	defer ap.RUnlock()

	return ap.withKeyMaterial
}

func (ap *AccessPoint) NumHandshakes() int {
	ap.RLock()
	defer ap.RUnlock()

	sum := 0

	for _, c := range ap.clients {
		if c.Handshake.Complete() {
			sum++
		}
	}

	return sum
}

func (ap *AccessPoint) HasHandshakes() bool {
	return ap.NumHandshakes() > 0
}

func (ap *AccessPoint) HasPMKID() bool {
	ap.RLock()
	defer ap.RUnlock()

	for _, c := range ap.clients {
		if c.Handshake.HasPMKID() {
			return true
		}
	}

	return false
}
