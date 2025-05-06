package main

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"strings"

	"github.com/quay/claircore/pkg/tarfs"
	orasoci "oras.land/oras-go/v2/content/oci"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
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

func createOCITarget(ctx context.Context, gadgetBytes []byte) (*orasoci.ReadOnlyStore, error) {
	reader := bytes.NewReader(gadgetBytes)
	fs, err := tarfs.New(reader)
	if err != nil {
		return nil, err
	}

	target, err := orasoci.NewFromFS(ctx, fs)
	if err != nil {
		return nil, fmt.Errorf("getting oci store from bytes: %w", err)
	}

	return target, nil
}

func createGadgetContext(ctx context.Context, gadgetBytes []byte, gadgetImageName string, dataOperators []operators.DataOperator) (*gadgetcontext.GadgetContext, error) {
	target, err := createOCITarget(ctx, gadgetBytes)
	if err != nil {
		return nil, fmt.Errorf("creating oci target: %w", err)
	}

	gadgetCtx := gadgetcontext.New(
		ctx,
		gadgetImageName,
		gadgetcontext.WithDataOperators(append([]operators.DataOperator{ocihandler.OciHandler}, dataOperators...)...),
		gadgetcontext.WithOrasReadonlyTarget(target),
	)

	return gadgetCtx, nil
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runtime, err := initRuntime()
	if err != nil {
		fmt.Errorf("initializing ig runtime: %s", err)
	}
	defer runtime.Close()

	jsonOperator := simple.New("jsonOperator",
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				jsonFormatter, _ := igjson.New(d,
					igjson.WithShowAll(true))

				d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					jsonOutput := jsonFormatter.Marshal(data)
					fmt.Printf("%s\n", jsonOutput)
					return nil
				}, 50000)
			}
			return nil
		}),
	)

	traceExecDataOperator := simple.New("jsonOperator",
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
				}, 40000); err != nil {
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
		fmt.Errorf("init local manager: %w", err)
	}
	defer localManagerOp.Close()

	execGadgetContext, err := createGadgetContext(ctx, traceExecBytes, traceExecGadgetImage, []operators.DataOperator{traceExecDataOperator, jsonOperator})
	if err != nil {
		fmt.Printf("creating exec gadget context: %s", err)
	}

	dnsGadgetContext, err := createGadgetContext(ctx, traceDnsBytes, traceDnsGadgetImage, []operators.DataOperator{localManagerOp, jsonOperator})
	if err != nil {
		fmt.Printf("creating dns gadget context: %s", err)
	}

	params := map[string]string{
		"operator.LocalManager.host": "true",
	}

	go runtime.RunGadget(dnsGadgetContext, nil, params)

	go runtime.RunGadget(execGadgetContext, nil, nil)

	select {}
}
