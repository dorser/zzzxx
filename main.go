package main

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/quay/claircore/pkg/tarfs"
	orasoci "oras.land/oras-go/v2/content/oci"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

//go:embed build/trace_exec.tar
var traceExecBytes []byte

const (
	gadgetImage = "github.com/dorser/zzzxxx/gadgets/trace_exec"
	opPriority  = 50000
)

type execTracer struct {
	ctx     context.Context
	runtime *local.Runtime
}

func (t *execTracer) initRuntime() error {
	t.runtime = local.New()
	if err := t.runtime.Init(nil); err != nil {
		return fmt.Errorf("runtime init: %w", err)
	}
	return nil
}

func (t *execTracer) createOCITarget() (*orasoci.ReadOnlyStore, error) {
	reader := bytes.NewReader(traceExecBytes)
	fs, err := tarfs.New(reader)
	if err != nil {
		return nil, err
	}

	target, err := orasoci.NewFromFS(t.ctx, fs)
	if err != nil {
		return nil, fmt.Errorf("getting oci store from bytes: %w", err)
	}

	return target, nil
}

func (t *execTracer) createJSONOperator() operators.DataOperator {
	return simple.New("jsonOperator",
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				jsonFormatter, _ := igjson.New(d,
					igjson.WithShowAll(true))

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

					jsonOutput := jsonFormatter.Marshal(data)
					fmt.Printf("%s\n", jsonOutput)
					return nil
				}, opPriority); err != nil {
					return fmt.Errorf("subscribing to data sources: %w", err)
				}
			}
			return nil
		}),
	)
}

func (t *execTracer) Run() error {
	ctx, cancel := context.WithTimeout(t.ctx, time.Hour)
	defer cancel()
	t.ctx = ctx

	if err := t.initRuntime(); err != nil {
		return err
	}
	defer t.runtime.Close()

	target, err := t.createOCITarget()
	if err != nil {
		return err
	}

	gadgetCtx := gadgetcontext.New(
		t.ctx,
		gadgetImage,
		gadgetcontext.WithDataOperators(ocihandler.OciHandler, t.createJSONOperator()),
		gadgetcontext.WithOrasReadonlyTarget(target),
	)

	if err := t.runtime.RunGadget(gadgetCtx, nil, nil); err != nil {
		return fmt.Errorf("running gadget: %w", err)
	}

	return nil
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	execTracer := &execTracer{
		ctx: ctx,
	}

	if err := execTracer.Run(); err != nil {
		fmt.Printf("running exec tracer: %s", err)
		os.Exit(1)
	}
}
