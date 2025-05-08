package operators

import (
	"fmt"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	igoperators "github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/localmanager"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// DataOperator is an alias for igoperators.DataOperator to avoid direct dependency in main
type DataOperator = igoperators.DataOperator

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
				if argsF == nil {
					return fmt.Errorf("args field not found in data source")
				}

				argsSize := d.GetField("args_size")
				if argsSize == nil {
					return fmt.Errorf("args_size field not found in data source")
				}

				if err := d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					argsBytes, err := argsF.Bytes(data)
					if err != nil {
						return fmt.Errorf("getting args bytes: %w", err)
					}

					argsSizeVal, err := argsSize.Uint32(data)
					if err != nil {
						return fmt.Errorf("getting args size: %w", err)
					}

					args := []string{}
					buf := []byte{}
					for i := 0; i < int(argsSizeVal); i++ {
						c := argsBytes[i]
						if c == 0 {
							args = append(args, string(buf))
							buf = []byte{}
						} else {
							buf = append(buf, c)
						}
					}

					if err := argsF.Set(data, []byte(strings.Join(args, " "))); err != nil {
						return fmt.Errorf("setting processed args: %w", err)
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

// NewLocalManager creates and initializes a local manager operator
func NewLocalManager() (igoperators.DataOperator, error) {
	host.Init(host.Config{})
	localManagerOp := localmanager.LocalManagerOperator
	localManagerParams := localManagerOp.GlobalParamDescs().ToParams()

	if err := localManagerOp.Init(localManagerParams); err != nil {
		return nil, fmt.Errorf("init local manager: %w", err)
	}
	return localManagerOp, nil
}

// NewOCIHandler creates and returns the OCI handler operator
func NewOCIHandler() igoperators.DataOperator {
	return ocihandler.OciHandler
}
