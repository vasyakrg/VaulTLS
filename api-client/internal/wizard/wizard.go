package wizard

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"text/template"
)

type Answers struct {
	URL      string
	ClientID string
	Secret   string
	Domain   string
	Reload   string
}

const tmpl = `server:
  url: {{ .URL }}
  client_id: {{ .ClientID }}
  secret: {{ .Secret }}
schedule: "0 3 1 * *"
exporter:
  listen: "127.0.0.1:9105"
domains:
  - name: "{{ .Domain }}"
    formats: [pem]
    reload: "{{ .Reload }}"
`

func Render(a Answers) ([]byte, error) {
	t, err := template.New("config").Parse(tmpl)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	if err := t.Execute(&b, a); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
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
