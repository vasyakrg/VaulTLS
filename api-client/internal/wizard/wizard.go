package wizard

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"
)

type Answers struct {
	URL      string
	ClientID string
	Secret   string
	Domain   string
	Reload   string
}

type renderDoc struct {
	Server struct {
		URL      string `yaml:"url"`
		ClientID string `yaml:"client_id"`
		Secret   string `yaml:"secret"`
	} `yaml:"server"`
	Schedule string `yaml:"schedule"`
	Exporter struct {
		Listen string `yaml:"listen"`
	} `yaml:"exporter"`
	Domains []renderDomain `yaml:"domains"`
}

type renderDomain struct {
	Name    string   `yaml:"name"`
	Formats []string `yaml:"formats"`
	Reload  string   `yaml:"reload"`
}

func Render(a Answers) ([]byte, error) {
	var doc renderDoc
	doc.Server.URL = a.URL
	doc.Server.ClientID = a.ClientID
	doc.Server.Secret = a.Secret
	doc.Schedule = "0 3 1 * *"
	doc.Exporter.Listen = "127.0.0.1:9105"
	doc.Domains = []renderDomain{{
		Name:    a.Domain,
		Formats: []string{"pem"},
		Reload:  a.Reload,
	}}
	return yaml.Marshal(&doc)
}

// RunInteractive prompts only for fields empty in preset.
func RunInteractive(in io.Reader, out io.Writer, preset Answers) (Answers, error) {
	r := bufio.NewReader(in)
	ask := func(label string, cur *string) error {
		if *cur != "" {
			return nil
		}
		fmt.Fprintf(out, "%s: ", label)
		line, err := r.ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("read %s: %w", label, err)
		}
		*cur = strings.TrimSpace(line)
		return nil
	}
	for _, f := range []struct {
		label string
		ptr   *string
	}{
		{"VaulTLS URL", &preset.URL},
		{"Client ID", &preset.ClientID},
		{"Secret", &preset.Secret},
		{"Domain (cert name, e.g. *.example.com)", &preset.Domain},
		{"Reload command", &preset.Reload},
	} {
		if err := ask(f.label, f.ptr); err != nil {
			return preset, err
		}
	}
	return preset, nil
}
