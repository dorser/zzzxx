package operators

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"time"

	"github.com/Azure/azure-kusto-go/kusto"
	"github.com/Azure/azure-kusto-go/kusto/ingest"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	igoperators "github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
)

// KustoConfig holds the configuration for the Kusto operator
type KustoConfig struct {
	ClusterURL    string
	Database      string
	Table         string
	ClientID      string
	ClientSecret  string
	TenantID      string
	Ctx           context.Context
	Mapping       string
	BatchInterval time.Duration
}

// NewKustoOperator creates an operator that sends data to Azure Data Explorer (Kusto)
func NewKustoOperator(config *KustoConfig) (igoperators.DataOperator, error) {
	kcsb := kusto.NewConnectionStringBuilder(config.ClusterURL).WithAzCli()
	client, err := kusto.New(kcsb)
	if err != nil {
		fmt.Errorf("failed to create client: %w", err)
		return nil, err
	}
	// defer client.Close()

	in, err := ingest.New(client, config.Database, config.Table)
	if err != nil {
		return nil, err
	}
	// defer in.Close()

	opPriority := math.MaxInt

	return simple.New("kustoOperator",
		simple.WithPriority(opPriority),
		simple.OnInit(func(gadgetCtx igoperators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				jsonFormatter, err := igjson.New(d,
					igjson.WithShowAll(true))
				if err != nil {
					return fmt.Errorf("creating json formatter: %w", err)
				}

				if err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					jsonOutput := jsonFormatter.Marshal(data)
					if jsonOutput != nil {
						//Emit to Kusto?
						_, err := in.FromReader(config.Ctx, bytes.NewReader(jsonOutput), ingest.IngestionMappingRef(config.Mapping, ingest.JSON))
						if err != nil {
							fmt.Printf("failed to send events %v", err)
						}

					}
					return nil
				}, opPriority); err != nil {
					return fmt.Errorf("subscribing to data source: %w", err)
				}
			}
			return nil
		}),
	), nil
}
