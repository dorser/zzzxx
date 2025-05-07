package gadget

import (
	"bytes"
	"context"
	"fmt"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/quay/claircore/pkg/tarfs"
	orasoci "oras.land/oras-go/v2/content/oci"
)

// CreateContext creates a new gadget context with the given configuration
func CreateContext(ctx context.Context, gadgetBytes []byte, gadgetImageName string, dataOperators []operators.DataOperator) (*gadgetcontext.GadgetContext, error) {
	// Create OCI target from gadget bytes
	reader := bytes.NewReader(gadgetBytes)
	fs, err := tarfs.New(reader)
	if err != nil {
		return nil, fmt.Errorf("creating tarfs: %w", err)
	}

	target, err := orasoci.NewFromFS(ctx, fs)
	if err != nil {
		return nil, fmt.Errorf("getting oci store from bytes: %w", err)
	}

	// Create gadget context with operators
	gadgetCtx := gadgetcontext.New(
		ctx,
		gadgetImageName,
		gadgetcontext.WithDataOperators(dataOperators...),
		gadgetcontext.WithOrasReadonlyTarget(target),
	)

	return gadgetCtx, nil
}
