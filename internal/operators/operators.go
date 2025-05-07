package operators

import (
	"fmt"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	igoperators "github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
)

// NewJSONOperator creates an operator that formats gadget output as JSON
func NewJSONOperator() igoperators.DataOperator {
	return simple.New("jsonOperator",
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
						fmt.Printf("%s\n", jsonOutput)
					}
					return nil
				}, 50000); err != nil { // Lower priority to run last
					return fmt.Errorf("subscribing to data source: %w", err)
				}
			}
			return nil
		}),
	)
}

// NewTraceExecOperator creates an operator that processes exec trace data
func NewTraceExecOperator() igoperators.DataOperator {
	return simple.New("traceExecOperator",
		simple.OnInit(func(gadgetCtx igoperators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				argsF := d.GetField("args")
				argsSize := d.GetField("args_size")

				if err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					argsBytes, err := argsF.Bytes(data)
					if err != nil {
						fmt.Printf("getting args: %s", err)
					}

					argsSize, err := argsSize.Uint32(data)
					if err != nil {
						fmt.Printf("getting args_size: %s", err)
					}

					args := []string{}
					buf := []byte{}
					for i := 0; i < int(argsSize); i++ {
						c := argsBytes[i]
						if c == 0 {
							args = append(args, string(buf))
							buf = []byte{}
						} else {
							buf = append(buf, c)
						}
					}

					if err := argsF.Set(data, []byte(strings.Join(args, " "))); err != nil {
						fmt.Printf("setting args: %s", err)
					}

					return nil
				}, 100); err != nil { // Higher priority to run first
					return fmt.Errorf("subscribing to data sources: %w", err)
				}
			}
			return nil
		}),
	)
}
