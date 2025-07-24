package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"testing"
)

func Test_f(t *testing.T) {
	data, err := ioutil.ReadFile("test_env.json")
	if err != nil {
		fmt.Println("Config read error:", err)
		return
	}
	config := ServiceConfig{}
	err = json.Unmarshal(data, &config)
	if err != nil {
		panic(err)
	}
}
