//go:generate ../../../tools/readme_config_includer/generator
package p4runtime

import (
	"context"
	"crypto/tls"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"

	p4_config "github.com/p4lang/p4runtime/go/p4/config/v1"
	p4 "github.com/p4lang/p4runtime/go/p4/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/influxdata/telegraf"
	common_tls "github.com/influxdata/telegraf/plugins/common/tls"
	"github.com/influxdata/telegraf/plugins/inputs"
)

//go:embed sample.conf
var sampleConfig string

const (
	defaultDeviceID = 1
	defaultEndpoint = "127.0.0.1:9559"
)

type P4runtime struct {
	Endpoint            string          `toml:"endpoint"`
	DeviceID            uint64          `toml:"device_id"`
	CounterNamesInclude []string        `toml:"counter_names_include"`
	Log                 telegraf.Logger `toml:"-"`
	EnableTLS           bool            `toml:"enable_tls"`
	common_tls.ClientConfig

	conn   *grpc.ClientConn
	client p4.P4RuntimeClient
	wg     sync.WaitGroup
}

func (*P4runtime) SampleConfig() string {
	return sampleConfig
}

func (p *P4runtime) Init() error {
	if p.Endpoint == "" {
		p.Log.Debugf("Using default Endpoint: %v", defaultEndpoint)
		p.Endpoint = defaultEndpoint
	}

	return p.newP4RuntimeClient()
}

func (p *P4runtime) Gather(acc telegraf.Accumulator) error {
	p4Info, err := p.getP4Info()
	if err != nil {
		return err
	}

	if len(p4Info.Counters) == 0 {
		p.Log.Warn("No counters available in P4 Program!")
		return nil
	}

	filteredCounters := filterCounters(p4Info.Counters, p.CounterNamesInclude)
	if len(filteredCounters) == 0 {
		p.Log.Warn("No filtered counters available in P4 Program!")
		return nil
	}

	for _, counter := range filteredCounters {
		p.wg.Add(1)
		go func(counter *p4_config.Counter) {
			defer p.wg.Done()
			entries, err := p.readAllEntries(counter.Preamble.Id)
			if err != nil {
				acc.AddError(
					fmt.Errorf(
						"reading counter entries with ID=%v failed with error: %w",
						counter.Preamble.Id,
						err,
					),
				)
				return
			}

			for _, entry := range entries {
				ce := entry.GetCounterEntry()

				if ce == nil {
					acc.AddError(fmt.Errorf("reading counter entry from entry %v failed", entry))
					continue
				}

				if ce.Data.ByteCount == 0 && ce.Data.PacketCount == 0 {
					continue
				}

				fields := map[string]interface{}{
					"bytes":         ce.Data.ByteCount,
					"packets":       ce.Data.PacketCount,
					"counter_index": ce.Index.Index,
				}

				tags := map[string]string{
					"p4program_name": p4Info.PkgInfo.Name,
					"counter_name":   counter.Preamble.Name,
					"counter_type":   counter.Spec.Unit.String(),
				}

				acc.AddFields("p4_runtime", fields, tags)
			}
		}(counter)
	}
	p.wg.Wait()
	return nil
}

func (p *P4runtime) Stop() {
	p.conn.Close()
	p.wg.Wait()
}

func initConnection(endpoint string, tlscfg *tls.Config) (*grpc.ClientConn, error) {
	var creds credentials.TransportCredentials
	if tlscfg != nil {
		creds = credentials.NewTLS(tlscfg)
	} else {
		creds = insecure.NewCredentials()
	}
	return grpc.NewClient(endpoint, grpc.WithTransportCredentials(creds))
}

func (p *P4runtime) getP4Info() (*p4_config.P4Info, error) {
	req := &p4.GetForwardingPipelineConfigRequest{
		DeviceId:     p.DeviceID,
		ResponseType: p4.GetForwardingPipelineConfigRequest_ALL,
	}
	resp, err := p.client.GetForwardingPipelineConfig(context.Background(), req)
	if err != nil {
		return nil, fmt.Errorf("error when retrieving forwarding pipeline config: %w", err)
	}

	config := resp.GetConfig()
	if config == nil {
		return nil, fmt.Errorf(
			"error when retrieving config from forwarding pipeline - pipeline doesn't have a config yet: %w",
			err,
		)
	}

	p4info := config.GetP4Info()
	if p4info == nil {
		return nil, fmt.Errorf(
			"error when retrieving P4Info from config - config doesn't have a P4Info: %w",
			err,
		)
	}

	return p4info, nil
}

func filterCounters(counters []*p4_config.Counter, counterNamesInclude []string) []*p4_config.Counter {
	if len(counterNamesInclude) == 0 {
		return counters
	}

	var filteredCounters []*p4_config.Counter
	for _, counter := range counters {
		if counter == nil {
			continue
		}
		if slices.Contains(counterNamesInclude, counter.Preamble.Name) {
			filteredCounters = append(filteredCounters, counter)
		}
	}
	return filteredCounters
}

func (p *P4runtime) newP4RuntimeClient() error {
	var tlscfg *tls.Config
	var err error

	if p.EnableTLS {
		if tlscfg, err = p.ClientConfig.TLSConfig(); err != nil {
			return err
		}
	}

	conn, err := initConnection(p.Endpoint, tlscfg)
	if err != nil {
		return fmt.Errorf("cannot connect to the server: %w", err)
	}
	p.conn = conn
	p.client = p4.NewP4RuntimeClient(conn)
	return nil
}

func (p *P4runtime) readAllEntries(counterID uint32) ([]*p4.Entity, error) {
	readRequest := &p4.ReadRequest{
		DeviceId: p.DeviceID,
		Entities: []*p4.Entity{{
			Entity: &p4.Entity_CounterEntry{
				CounterEntry: &p4.CounterEntry{
					CounterId: counterID}}}}}

	stream, err := p.client.Read(context.Background(), readRequest)
	if err != nil {
		return nil, err
	}

	rep, err := stream.Recv()
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	return rep.Entities, nil
}

func init() {
	inputs.Add("p4runtime", func() telegraf.Input {
		p4runtime := &P4runtime{
			DeviceID: defaultDeviceID,
		}
		return p4runtime
	})
}
