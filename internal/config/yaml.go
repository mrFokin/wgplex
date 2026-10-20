package config

import (
	"bytes"
	"errors"
	"io"

	yaml "go.yaml.in/yaml/v3"
)

// rawConfig mirrors wgplex.yaml (design 9.1). Optional fields are pointers
// so that defaults (design 9.2) can be told apart from explicit values.
type rawConfig struct {
	IPv6Filter *bool                 `yaml:"ipv6_filter"`
	Tunnels    []rawTunnel           `yaml:"tunnels"`
	Services   map[string]rawService `yaml:"services"`
	Rules      []rawRule             `yaml:"rules"`
}

type rawTunnel struct {
	Name       string   `yaml:"name"`
	Conf       string   `yaml:"conf"`
	Routes     string   `yaml:"routes"`
	Autostart  *bool    `yaml:"autostart"`
	DNSDomains []string `yaml:"dns_domains"`
	Check      string   `yaml:"check"`
}

type rawService struct {
	Domains []string `yaml:"domains"`
	CIDRs   []string `yaml:"cidrs"`
}

type rawRule struct {
	Services []string `yaml:"services"`
	Via      []string `yaml:"via"`
	Fallback string   `yaml:"fallback"`
}

// parseYAML decodes wgplex.yaml in strict mode: unknown keys are an error
// (yaml.Decoder.KnownFields, design 9.2).
// An empty document yields an empty rawConfig. The file must hold a single
// YAML document: a second one after "---" is an error (design 9.2).
func parseYAML(data []byte) (*rawConfig, error) {
	var raw rawConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return &raw, nil
		}
		return nil, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("multiple YAML documents, want one")
	}
	return &raw, nil
}
