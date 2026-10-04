package substore

import "testing"

// mihomo 规定 mieru 的 port 与 port-range 不能同时写:有范围就只留范围,没范围原样。
func TestClashMetaMieruDropsPortWhenRanged(t *testing.T) {
	out, err := NewClashMetaProducer().Produce([]Proxy{
		{"name": "ranged", "type": "mieru", "server": "1.2.3.4", "port": 20000, "port-range": "20000-20100", "username": "a", "password": "b", "transport": "TCP"},
		{"name": "single", "type": "mieru", "server": "1.2.3.4", "port": 20000, "username": "a", "password": "b", "transport": "TCP"},
	}, "internal", nil)
	if err != nil {
		t.Fatal(err)
	}
	list, ok := out.([]Proxy)
	if !ok || len(list) != 2 {
		t.Fatalf("产出: %T %v", out, out)
	}
	if _, has := list[0]["port"]; has || list[0]["port-range"] != "20000-20100" {
		t.Errorf("带范围应只留 port-range: %v", list[0])
	}
	if list[1]["port"] != 20000 {
		t.Errorf("单端口不应动: %v", list[1])
	}
}
