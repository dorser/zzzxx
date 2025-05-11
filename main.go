package main

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/dorser/zzzxx/internal/gadget"
	"github.com/dorser/zzzxx/internal/operators"
	"github.com/dorser/zzzxx/internal/runtime"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/socketenricher"
)

//go:embed build/trace_exec.tar
var traceExecBytes []byte

//go:embed build/trace_dns.tar
var traceDnsBytes []byte

const (
	traceExecGadgetImage = "github.com/dorser/zzzxxx/gadgets/trace_exec"
	traceDnsGadgetImage  = "github.com/dorser/zzzxxx/gadgets/trace_dns"
)

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

	// Initialize runtime manager
	runtimeManager, err := runtime.NewManager()
	if err != nil {
		fmt.Printf("initializing runtime manager: %w", err)
		os.Exit(1)
	}
	defer runtimeManager.Close()

	// Create operators
	jsonOp := operators.NewJSONOperator()
	traceExecOp := operators.NewTraceExecOperator()
	traceDnsOp := operators.NewTraceDnsOperator()
	ociOp := operators.NewOCIHandler()

	// Initialize local manager
	localManagerOp, err := operators.NewLocalManager()
	if err != nil {
		fmt.Printf("initializing local manager: %w", err)
		os.Exit(1)
	}

	kustoCluster := os.Getenv("KUSTO_CLUSTER_URL")
	kustoDatabase := os.Getenv("KUSTO_DATABASE")

	dnsKustoOp, _ := operators.NewKustoOperator(&operators.KustoConfig{
		ClusterURL: kustoCluster,
		Database:   kustoDatabase,
		Table:      os.Getenv("KUSTO_DNS_TABLE"),
		Mapping:    os.Getenv("KUSTO_DNS_MAPPING"),
		Ctx:        ctx,
	})

	execKustoOp, _ := operators.NewKustoOperator(&operators.KustoConfig{
		ClusterURL: kustoCluster,
		Database:   kustoDatabase,
		Table:      os.Getenv("KUSTO_EXEC_TABLE"),
		Mapping:    os.Getenv("KUSTO_EXEC_MAPPING"),
		Ctx:        ctx,
	})

	formattersOp, err := operators.NewFormattersOperator()
	if err != nil {
		fmt.Printf("initializing formatters operator")
		os.Exit(1)
	}

	// Create context managers with their respective operators
	execContextManager := gadget.NewContextManager([]operators.DataOperator{
		ociOp,
		traceExecOp,
		execKustoOp,
		formattersOp,
		jsonOp,
	})

	dnsContextManager := gadget.NewContextManager([]operators.DataOperator{
		ociOp,
		traceDnsOp,
		&socketenricher.SocketEnricher{},
		localManagerOp,
		dnsKustoOp,
		formattersOp,
		jsonOp,
	})

	// Create gadget registry
	registry := gadget.NewRegistry(nil, runtimeManager)

	// Register gadgets
	registry.Register("trace_exec", &gadget.GadgetConfig{
		Bytes:     traceExecBytes,
		ImageName: traceExecGadgetImage,
		Params:    nil,
		Context:   execContextManager,
	})

	registry.Register("trace_dns", &gadget.GadgetConfig{
		Bytes:     traceDnsBytes,
		ImageName: traceDnsGadgetImage,
		Params: map[string]string{
			"operator.LocalManager.host":          "true",
			"operator.LocalManager.ContainerName": "",
		},
		Context: dnsContextManager,
	})

	// Run all gadgets
	if err := registry.RunAll(ctx); err != nil {
		fmt.Printf("running gadgets: %w", err)
		os.Exit(1)
	}

	<-ctx.Done()
	fmt.Println("Shutting down...")
}
