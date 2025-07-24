package config

type ServiceConfig struct {
	Local BaseServerInfo   `json:"local_sever"`
	Agg   BaseServerInfo   `json:"agg_sever"`
	Sub   []BaseServerInfo `json:"sub_severs"`
	Node  string           `json:"neox_node"`
}

type BaseServerInfo struct {
	Address string `json:"address"`
	Port    string `json:"port"`
}
