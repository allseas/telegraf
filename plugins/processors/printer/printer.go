//go:generate ../../../tools/readme_config_includer/generator
package printer

import (
	_ "embed"
	"fmt"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/processors"
	"github.com/influxdata/telegraf/plugins/serializers/influx"
)

//go:embed sample.conf
var sampleConfig string

type Printer struct {
	influx.Serializer
}

func (*Printer) SampleConfig() string {
	return sampleConfig
}

func (p *Printer) Apply(in ...telegraf.Metric) []telegraf.Metric {
	for _, metric := range in {
		octets, err := p.Serialize(metric)
		if err != nil {
			continue
		}
		fmt.Print(string(octets))
	}
	return in
}

func init() {
	processors.Add("printer", func() telegraf.Processor {
		return &Printer{}
	})
}
