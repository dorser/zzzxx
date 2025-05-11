package operators

import (
	"fmt"
	"math"
	"net"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	igoperators "github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/formatters"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/localmanager"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
	"golang.org/x/net/dns/dnsmessage"
)

type RCode uint16

type Type uint16

const (
	// ResourceHeader.Type and Question.Type
	TypeA     Type = 1
	TypeNS    Type = 2
	TypeCNAME Type = 5
	TypeSOA   Type = 6
	TypePTR   Type = 12
	TypeMX    Type = 15
	TypeTXT   Type = 16
	TypeAAAA  Type = 28
	TypeSRV   Type = 33
	TypeOPT   Type = 41

	// Question.Type
	TypeWKS   Type = 11
	TypeHINFO Type = 13
	TypeMINFO Type = 14
	TypeAXFR  Type = 252
	TypeALL   Type = 255
)

var typeNames = map[Type]string{
	TypeA:     "A",
	TypeNS:    "NS",
	TypeCNAME: "CNAME",
	TypeSOA:   "SOA",
	TypePTR:   "PTR",
	TypeMX:    "MX",
	TypeTXT:   "TXT",
	TypeAAAA:  "AAAA",
	TypeSRV:   "SRV",
	TypeOPT:   "OPT",
	TypeWKS:   "WKS",
	TypeHINFO: "HINFO",
	TypeMINFO: "MINFO",
	TypeAXFR:  "AXFR",
	TypeALL:   "ALL",
}

// String implements fmt.Stringer.String.
func (t Type) String() string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("%d", t)
}

const (
	RCodeSuccess        RCode = 0 // NoError
	RCodeFormatError    RCode = 1 // FormErr
	RCodeServerFailure  RCode = 2 // ServFail
	RCodeNameError      RCode = 3 // NXDomain
	RCodeNotImplemented RCode = 4 // NotImp
	RCodeRefused        RCode = 5 // Refused
)

var rCodeNames = map[RCode]string{
	RCodeSuccess:        "Success",
	RCodeFormatError:    "FormatError",
	RCodeServerFailure:  "ServerFailure",
	RCodeNameError:      "NameError",
	RCodeNotImplemented: "NotImplemented",
	RCodeRefused:        "Refused",
}

// String implements fmt.Stringer.String.
func (r RCode) String() string {
	if n, ok := rCodeNames[r]; ok {
		return n
	}
	return fmt.Sprintf("%d", r)
}

// DataOperator is an alias for igoperators.DataOperator to avoid direct dependency in main
type DataOperator = igoperators.DataOperator

// NewJSONOperator creates an operator that formats gadget output as JSON
func NewJSONOperator() igoperators.DataOperator {
	opPriority := math.MaxInt
	return simple.New("jsonOperator",
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
						fmt.Printf("%s\n", jsonOutput)
					}
					return nil
				}, opPriority); err != nil { // Lower priority to run last
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

func NewTraceDnsOperator() igoperators.DataOperator {
	return simple.New("tracDnsOperator",
		simple.OnInit(func(gadgetCtx igoperators.GadgetContext) error {
			for _, ds := range gadgetCtx.GetDataSources() {
				dataF := ds.GetField("data")
				lenF := ds.GetField("data_len")
				dnsOffF := ds.GetField("dns_off")

				idF, err := ds.AddField("id", api.Kind_String)
				if err != nil {
					return err
				}

				qrRawF, err := ds.AddField("qr_raw", api.Kind_Bool)
				if err != nil {
					return err
				}

				qrF, err := ds.AddField("qr", api.Kind_String)
				if err != nil {
					return err
				}

				qtypeRawF, err := ds.AddField("qtype_raw", api.Kind_Uint16)
				if err != nil {
					return err
				}

				qtypeF, err := ds.AddField("qtype", api.Kind_String)
				if err != nil {
					return err
				}

				nameF, err := ds.AddField("name", api.Kind_String)
				if err != nil {
					return err
				}

				rcodeRawF, err := ds.AddField("rcode_raw", api.Kind_Uint16)
				if err != nil {
					return err
				}

				rcodeF, err := ds.AddField("rcode", api.Kind_String)
				if err != nil {
					return err
				}

				numAnswersF, err := ds.AddField("num_answers", api.Kind_Int32)
				if err != nil {
					return err
				}

				addressesF, err := ds.AddField("addresses", api.Kind_String)
				if err != nil {
					return err
				}

				//nolint:errcheck
				ds.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					// Get all fields sent by ebpf
					payloadLen, err := lenF.Uint32(data)
					if err != nil {
						return err
					}
					dnsOff, err := dnsOffF.Uint16(data)
					if err != nil {
						return err
					}

					if payloadLen < uint32(dnsOff) {
						return err
					}

					payload, err := dataF.Bytes(data)
					if err != nil {
						return err
					}

					msg := dnsmessage.Message{}
					if err := msg.Unpack(payload[dnsOff:]); err != nil {
						return err
					}

					if err := idF.PutString(data, fmt.Sprintf("%.4x", msg.ID)); err != nil {
						return err
					}

					if err := qrRawF.PutBool(data, msg.Header.Response); err != nil {
						return err
					}
					//nolint:nestif
					if msg.Header.Response {
						if err := rcodeRawF.PutUint16(data, uint16(msg.Header.RCode)); err != nil {
							return err
						}
						if err := rcodeF.PutString(data, RCode(msg.Header.RCode).String()); err != nil {
							return err
						}
						if err := qrF.PutString(data, "R"); err != nil {
							return err
						}
					} else {
						if err := qrF.PutString(data, "Q"); err != nil {
							return err
						}
					}

					if len(msg.Questions) > 0 {
						question := msg.Questions[0]
						if err := qtypeRawF.PutUint16(data, uint16(question.Type)); err != nil {
							return err
						}
						if err := qtypeF.PutString(data, Type(question.Type).String()); err != nil {
							return err
						}
						if err := nameF.PutString(data, question.Name.String()); err != nil {
							return err
						}
					}

					if err := numAnswersF.PutInt32(data, int32(len(msg.Answers))); err != nil {
						return err
					}

					var addresses []string
					for _, answer := range msg.Answers {
						var str string
						//nolint:exhaustive
						switch answer.Header.Type {
						case dnsmessage.TypeA:
							ipv4, ok := answer.Body.(*dnsmessage.AResource)
							if !ok {
								continue
							}
							str = net.IP(ipv4.A[:]).String()
						case dnsmessage.TypeAAAA:
							ipv6, ok := answer.Body.(*dnsmessage.AAAAResource)
							if !ok {
								continue
							}
							str = net.IP(ipv6.AAAA[:]).String()
						}
						if str != "" {
							addresses = append(addresses, str)
						}
					}

					if err := addressesF.PutString(data, strings.Join(addresses, ",")); err != nil {
						return err
					}

					return err
				}, 100)
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

func NewFormattersOperator() (igoperators.DataOperator, error) {
	return formatters.FormattersOperator, nil
}
