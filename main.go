package main

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/dorser/zzzxx/internal/gadget"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/localmanager"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

//go:embed build/trace_exec.tar
var traceExecBytes []byte

//go:embed build/trace_dns.tar
var traceDnsBytes []byte

const (
	traceExecGadgetImage = "github.com/dorser/zzzxxx/gadgets/trace_exec"
	traceDnsGadgetImage  = "github.com/dorser/zzzxxx/gadgets/trace_dns"
)

func initRuntime() (*local.Runtime, error) {
	runtime := local.New()
	if err := runtime.Init(nil); err != nil {
		return nil, fmt.Errorf("runtime init: %w", err)
	}
	return runtime, nil
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("Received shutdown signal")
		cancel()
	}()

	runtime, err := initRuntime()
	if err != nil {
		fmt.Printf("initializing ig runtime: %s", err)
		os.Exit(1)
	}
	defer runtime.Close()

	jsonOperator := simple.New("jsonOperator",
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
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
				}, 50000); err != nil {
					return fmt.Errorf("subscribing to data source: %w", err)
				}
			}
			return nil
		}),
	)

	traceExecDataOperator := simple.New("traceExecOperator",
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
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
				}, 100); err != nil {
					return fmt.Errorf("subscribing to data sources: %w", err)
				}
			}
			return nil
		}),
	)

	host.Init(host.Config{})
	localManagerOp := localmanager.LocalManagerOperator
	localManagerParams := localManagerOp.GlobalParamDescs().ToParams()

	if err := localManagerOp.Init(localManagerParams); err != nil {
		fmt.Printf("init local manager: %w", err)
		os.Exit(1)
	}
	defer localManagerOp.Close()

	// Create gadget contexts using the new function
	execGadgetContext, err := gadget.CreateContext(ctx, traceExecBytes, traceExecGadgetImage,
		[]operators.DataOperator{ocihandler.OciHandler, traceExecDataOperator, jsonOperator})
	if err != nil {
		fmt.Printf("creating exec gadget context: %s", err)
		os.Exit(1)
	}

	dnsGadgetContext, err := gadget.CreateContext(ctx, traceDnsBytes, traceDnsGadgetImage,
		[]operators.DataOperator{ocihandler.OciHandler, localManagerOp, jsonOperator})
	if err != nil {
		fmt.Printf("creating dns gadget context: %s", err)
		os.Exit(1)
	}

	params := map[string]string{
		"operator.LocalManager.host": "true",
	}

	go runtime.RunGadget(dnsGadgetContext, nil, params)
	go runtime.RunGadget(execGadgetContext, nil, nil)

	<-ctx.Done()
	fmt.Println("Shutting down...")
}
