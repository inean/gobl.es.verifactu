// Package main provides the gateway-facing command surface for VeriFactu.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/invopop/gobl"
	verifactu "github.com/invopop/gobl.es.verifactu"
	verifactuaddon "github.com/invopop/gobl.es.verifactu/addon"
	"github.com/invopop/gobl/bill"
	"github.com/invopop/xmldsig"
	"github.com/spf13/cobra"
	"software.sslmate.com/src/go-pkcs12"
)

const laneGatewayOperationContractVersion = "plazia.compliance.lane-gateway.operation.v1"
const laneWorkerResultContractVersion = "plazia.compliance.lane-worker-result.v1"

const (
	envLaneWorkerOperationID     = "PLZC_LANE_WORKER_OPERATION_ID"
	envLaneWorkerExecutionMode   = "PLZC_LANE_WORKER_EXECUTION_MODE"
	envAuthorityTimeoutSeconds   = "PLZC_LANE_GATEWAY_AUTHORITY_TIMEOUT_SECONDS"
	envAeatPreviousChainDataJSON = "PLZC_VERIFACTU_PREVIOUS_CHAIN_DATA_JSON"
	envAeatOperationType         = "PLZC_VERIFACTU_OPERATION_TYPE"
	defaultLaneWorkerRetryAfter  = 60
	executionModeCapture         = "capture"
	executionModeDeterministic   = "deterministic"
	executionModeDryRun          = "dry-run"
	executionModeHTTP            = "http"
	executionModeLive            = "live"
	executionModeSend            = "send"
	artifactPurposeAeatRequest   = "aeat_request"
	artifactPurposeAeatResponse  = "aeat_response"
	operationTypeRegister        = "register"
	operationTypeCancel          = "cancel"
)

type gatewayOpts struct {
	*rootOpts
	operationID    string
	operationType  string
	executionMode  string
	previous       string
	timeoutSeconds int
	certDER        string
	keyDER         string
	clientOptions  []verifactu.Option
	sendInvoice    func(*verifactu.Client, context.Context, *verifactu.InvoiceRequest) (*verifactu.InvoiceResponse, error)
}

type laneWorkerResult struct {
	Head      laneWorkerResultHead `json:"head"`
	Chain     map[string]any       `json:"chain,omitempty"`
	Artifacts []laneWorkerArtifact `json:"artifacts,omitempty"`
	Retry     *laneWorkerRetry     `json:"retry,omitempty"`
	Error     *laneWorkerError     `json:"error,omitempty"`
}

type laneWorkerResultHead struct {
	Contract string `json:"contract"`
	ID       string `json:"id"`
	Status   string `json:"status"`
}

type laneWorkerArtifact struct {
	Purpose  string                     `json:"purpose"`
	Contents map[string]any             `json:"contents,omitempty"`
	Private  *laneWorkerPrivateArtifact `json:"private,omitempty"`
}

type laneWorkerPrivateArtifact struct {
	Type string `json:"type"`
	B64  string `json:"b64"`
}

type laneWorkerRetry struct {
	AfterSeconds int `json:"after_seconds"`
}

type laneWorkerError struct {
	Category string `json:"category"`
	Code     string `json:"code"`
}

type capturedInvoiceRequest struct {
	Payload          []byte
	PayloadMediaType string
	RecordCount      int
	OperationType    string
	Verification     map[string]any
}

type laneWorkerResultBuilder struct {
	operationID string
}

func gateway(o *rootOpts, options ...verifactu.Option) *gatewayOpts {
	return &gatewayOpts{
		rootOpts:      o,
		clientOptions: options,
		sendInvoice:   (*verifactu.Client).SendInvoiceRequest,
	}
}

func (c *gatewayOpts) cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gateway",
		Short: "Runs the lane-gateway JSON result mode",
		Args:  cobra.NoArgs,
		RunE:  c.runE,
	}

	f := cmd.Flags()
	c.prepareFlags(f)
	f.StringVar(&c.operationID, "operation-id", os.Getenv(envLaneWorkerOperationID), "Lane gateway operation id")
	f.StringVar(&c.operationType, "operation-type", os.Getenv(envAeatOperationType), "AEAT VERI*FACTU operation type: register or cancel")
	f.StringVar(&c.executionMode, "execution-mode", os.Getenv(envLaneWorkerExecutionMode), "Lane worker execution mode")
	f.StringVar(&c.previous, "prev", os.Getenv(envAeatPreviousChainDataJSON), "Previous invoice chain data as JSON")
	f.IntVar(&c.timeoutSeconds, "authority-timeout-seconds", intEnv(envAuthorityTimeoutSeconds, 0), "Authority call timeout in seconds")
	f.StringVar(&c.certDER, "cert-der", os.Getenv("CERTIFICATE_DER_PATH"), "DER certificate for lane gateway execution")
	f.StringVar(&c.keyDER, "key-der", os.Getenv("CERTIFICATE_PRIVATE_KEY_DER_PATH"), "DER private key for lane gateway execution")

	return cmd
}

func (c *gatewayOpts) runE(cmd *cobra.Command, _ []string) error {
	operationID := strings.TrimSpace(c.operationID)
	if operationID == "" {
		return fmt.Errorf("lane gateway operation id is required")
	}
	results := laneWorkerResults(operationID)

	envelope, err := readGatewayEnvelope(cmd.InOrStdin())
	if err != nil {
		return writeGatewayResult(cmd.OutOrStdout(), results.invalid(err))
	}
	previous, err := previousChainDataFromJSON(c.previous)
	if err != nil {
		return writeGatewayResult(cmd.OutOrStdout(), results.invalid(err))
	}

	ctx := cmd.Context()
	var cancel context.CancelFunc
	if c.timeoutSeconds > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(c.timeoutSeconds)*time.Second)
		defer cancel()
	}

	result := c.execute(ctx, operationID, envelope, previous)
	return writeGatewayResult(cmd.OutOrStdout(), result)
}

func (c *gatewayOpts) execute(
	ctx context.Context,
	operationID string,
	envelope *gobl.Envelope,
	previous *verifactu.ChainData,
) (result laneWorkerResult) {
	mode := normalizedExecutionMode(c.executionMode)
	operationType := normalizedOperationType(c.operationType)
	results := laneWorkerResults(operationID)
	ctx, span := c.startLaneOperationSpan(ctx, mode, operationType)
	defer func() {
		finishLaneOperationSpan(span, result)
		span.End()
	}()
	if err := validateOperationType(operationType); err != nil {
		return results.invalid(err)
	}
	if mode == executionModeSend || mode == executionModeHTTP || mode == executionModeLive {
		if c.cert == "" && c.certDER == "" && c.keyDER == "" {
			return results.pending(
				"lane_worker_unavailable",
				"lane_worker_configuration",
				"lane_worker_unavailable",
				defaultLaneWorkerRetryAfter,
			)
		}
	}
	client, err := c.clientForGatewayExecution(mode)
	if err != nil {
		return results.pending(
			"lane_worker_unavailable",
			"lane_worker_configuration",
			"lane_worker_unavailable",
			defaultLaneWorkerRetryAfter,
		)
	}

	switch mode {
	case executionModeSend, executionModeHTTP, executionModeLive:
		request, chainData, err := buildInvoiceRequest(client, envelope, previous, operationType)
		if err != nil {
			return results.invalid(err)
		}
		response, err := c.submitInvoice(ctx, client, request)
		if err != nil {
			return results.fromError(err)
		}
		return results.fromInvoiceResponse(
			response,
			publicVerificationContent(chainData, envelope),
		)
	case executionModeCapture, executionModeDeterministic, executionModeDryRun:
		capture, err := captureInvoiceRequest(client, envelope, previous, operationType)
		if err != nil {
			return results.invalid(err)
		}
		return results.fromCapture(capture)
	default:
		return results.invalid(fmt.Errorf("unsupported lane worker execution mode"))
	}
}

func (c *gatewayOpts) clientForGatewayExecution(mode string) (*verifactu.Client, error) {
	options, err := c.gatewayClientOptions(mode)
	if err != nil {
		return nil, err
	}
	return verifactu.New(c.software(), append(options, c.clientOptions...)...)
}

func (c *gatewayOpts) gatewayClientOptions(mode string) ([]verifactu.Option, error) {
	options := []verifactu.Option{}
	needsCertificate := c.sign || mode == executionModeSend ||
		mode == executionModeHTTP ||
		mode == executionModeLive
	if needsCertificate && (c.certDER != "" || c.keyDER != "") {
		if strings.TrimSpace(c.certDER) == "" || strings.TrimSpace(c.keyDER) == "" {
			return nil, fmt.Errorf("DER certificate and private key are required")
		}
		certificateDER, err := os.ReadFile(c.certDER)
		if err != nil {
			return nil, fmt.Errorf("reading DER certificate: %w", err)
		}
		privateKeyDER, err := os.ReadFile(c.keyDER)
		if err != nil {
			return nil, fmt.Errorf("reading DER private key: %w", err)
		}
		cert, err := loadGatewayCertificate(certificateDER, privateKeyDER)
		if err != nil {
			return nil, fmt.Errorf("loading DER certificate: %w", err)
		}
		options = append(options, verifactu.WithCertificate(cert))
	} else if needsCertificate && c.cert != "" {
		cert, err := xmldsig.LoadCertificate(c.cert, c.password)
		if err != nil {
			return nil, fmt.Errorf("loading certificate: %w", err)
		}
		options = append(options, verifactu.WithCertificate(cert))
	}
	if c.sign {
		options = append(options, verifactu.WithSigning())
	}
	if c.production {
		options = append(options, verifactu.InProduction())
	} else {
		options = append(options, verifactu.InSandbox())
	}
	return options, nil
}

func loadGatewayCertificate(certDER, keyDER []byte) (*xmldsig.Certificate, error) {
	pair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		return nil, err
	}
	cert := pair.Leaf
	if cert == nil {
		cert, err = x509.ParseCertificate(certDER)
		if err != nil {
			return nil, err
		}
	}
	// The upstream signing library accepts PKCS#12 bytes. Keep the
	// intermediate representation in memory for the lifetime of this call.
	p12, err := pkcs12.Passwordless.Encode(pair.PrivateKey, cert, nil, "")
	if err != nil {
		return nil, err
	}
	defer clear(p12)
	return xmldsig.LoadCertificateFromBytes(p12, "")
}

func readGatewayEnvelope(input io.Reader) (*gobl.Envelope, error) {
	body, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("reading GOBL envelope: %w", err)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("missing GOBL envelope")
	}
	envelope := new(gobl.Envelope)
	if err := json.Unmarshal(body, envelope); err != nil {
		return nil, fmt.Errorf("unmarshaling GOBL envelope: %w", err)
	}
	return envelope, nil
}

func previousChainDataFromJSON(value string) (*verifactu.ChainData, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	previous := new(verifactu.ChainData)
	if err := json.Unmarshal([]byte(value), previous); err != nil {
		return nil, fmt.Errorf("previous chain data: %w", err)
	}
	if strings.TrimSpace(previous.IDIssuer) == "" ||
		strings.TrimSpace(previous.NumSeries) == "" ||
		strings.TrimSpace(previous.IssueDate) == "" ||
		strings.TrimSpace(previous.Fingerprint) == "" {
		return nil, fmt.Errorf("previous chain data is incomplete")
	}
	return previous, nil
}

func buildInvoiceRequest(
	client *verifactu.Client,
	envelope *gobl.Envelope,
	previous *verifactu.ChainData,
	operationType string,
) (*verifactu.InvoiceRequest, *verifactu.ChainData, error) {
	var request *verifactu.InvoiceRequest
	var err error
	switch operationType {
	case operationTypeRegister:
		request, err = client.NewEnvelopeInvoiceRequest(envelope, previous)
	case operationTypeCancel:
		request, err = buildInvoiceCancellationRequest(client, envelope, previous)
	default:
		return nil, nil, fmt.Errorf("unsupported AEAT VERI*FACTU operation type")
	}
	if err != nil {
		return nil, nil, err
	}
	if len(request.Lines) == 0 || request.Lines[len(request.Lines)-1] == nil {
		return nil, nil, fmt.Errorf("invoice request did not include a record")
	}
	return request, request.Lines[len(request.Lines)-1].ChainData(), nil
}

func buildInvoiceCancellationRequest(
	client *verifactu.Client,
	envelope *gobl.Envelope,
	previous *verifactu.ChainData,
) (*verifactu.InvoiceRequest, error) {
	cancellation, err := client.CancelInvoice(envelope, previous)
	if err != nil {
		return nil, err
	}
	invoice, ok := envelope.Extract().(*bill.Invoice)
	if !ok {
		return nil, verifactu.ErrOnlyInvoices
	}
	request, err := client.NewInvoiceRequest(invoice.Supplier)
	if err != nil {
		return nil, err
	}
	request.AddCancellation(cancellation)
	return request, nil
}

func captureInvoiceRequest(
	client *verifactu.Client,
	envelope *gobl.Envelope,
	previous *verifactu.ChainData,
	operationType string,
) (*capturedInvoiceRequest, error) {
	request, chainData, err := buildInvoiceRequest(client, envelope, previous, operationType)
	if err != nil {
		return nil, err
	}
	payload, err := request.Envelop().BytesIndent()
	if err != nil {
		return nil, err
	}
	return &capturedInvoiceRequest{
		Payload:          payload,
		PayloadMediaType: "application/xml",
		RecordCount:      len(request.Lines),
		OperationType:    operationType,
		Verification:     publicVerificationContent(chainData, envelope),
	}, nil
}

func laneWorkerResults(operationID string) laneWorkerResultBuilder {
	return laneWorkerResultBuilder{operationID: operationID}
}

func (b laneWorkerResultBuilder) result(status string) laneWorkerResult {
	return laneWorkerResult{
		Head: laneWorkerResultHead{
			Contract: laneWorkerResultContractVersion,
			ID:       b.operationID,
			Status:   status,
		},
	}
}

func (b laneWorkerResultBuilder) fromCapture(
	capture *capturedInvoiceRequest,
) laneWorkerResult {
	result := b.result("PENDING")
	result.Chain = capture.Verification
	result.Artifacts = []laneWorkerArtifact{
		captureEvidenceArtifact(capture),
	}
	return result
}

func captureEvidenceArtifact(
	capture *capturedInvoiceRequest,
) laneWorkerArtifact {
	return laneWorkerArtifact{
		Purpose: artifactPurposeAeatRequest,
		Contents: map[string]any{
			"operation_type": capture.OperationType,
			"record_count":   capture.RecordCount,
		},
		Private: privateArtifact(capture.PayloadMediaType, capture.Payload),
	}
}

func chainDataContent(chainData *verifactu.ChainData) map[string]any {
	if chainData == nil {
		return nil
	}
	return map[string]any{
		"issuer":      chainData.IDIssuer,
		"num_series":  chainData.NumSeries,
		"issue_date":  chainData.IssueDate,
		"fingerprint": chainData.Fingerprint,
	}
}

func publicVerificationContent(
	chainData *verifactu.ChainData,
	envelope *gobl.Envelope,
) map[string]any {
	content := chainDataContent(chainData)
	if content == nil {
		content = make(map[string]any)
	}
	if envelope != nil && envelope.Head != nil {
		for _, stamp := range envelope.Head.Stamps {
			if stamp != nil && stamp.Provider == verifactuaddon.StampQR {
				content["qr_provider"] = stamp.Provider.String()
				content["qr_payload"] = stamp.Value
				break
			}
		}
	}
	if len(content) == 0 {
		return nil
	}
	return content
}

func (b laneWorkerResultBuilder) fromInvoiceResponse(
	response *verifactu.InvoiceResponse,
	verification map[string]any,
) laneWorkerResult {
	status, errorCategory, errorCode := responseError(response)
	var responseArtifact laneWorkerArtifact
	var artifactErr error
	if response != nil {
		responseArtifact, artifactErr = authorityResponseArtifact(response)
		responseArtifact.Contents = duplicateContents(response)
	}
	if artifactErr != nil {
		return b.nonRetryable(
			"REQUIRES_INSPECTION",
			"authority_technical_schema_fault",
			"authority_response_marshal",
		)
	}
	if errorCategory != "" {
		result := b.nonRetryable(status, errorCategory, errorCode)
		if responseArtifact.Purpose != "" {
			result.Artifacts = []laneWorkerArtifact{responseArtifact}
		}
		return result
	}
	result := b.result("REGISTERED")
	result.Chain = verification
	result.Artifacts = []laneWorkerArtifact{responseArtifact}
	return result
}

func authorityResponseArtifact(response *verifactu.InvoiceResponse) (laneWorkerArtifact, error) {
	responseXML, err := response.Bytes()
	if err != nil {
		return laneWorkerArtifact{}, err
	}
	return laneWorkerArtifact{
		Purpose: artifactPurposeAeatResponse,
		Private: privateArtifact(
			"application/xml",
			responseXML,
		),
	}, nil
}

func responseError(response *verifactu.InvoiceResponse) (status, category, code string) {
	if response == nil || len(response.Lines) == 0 {
		return "INVALID", "authority_technical_schema_fault", "missing_response_line"
	}
	for _, line := range response.Lines {
		if line == nil {
			return "INVALID", "authority_technical_schema_fault", "missing_response_line"
		}
		if line.Duplicated != nil {
			if line.Operation.Type == verifactu.OpTypeRegistration &&
				strings.TrimSpace(line.Duplicated.Status) == verifactu.StatusCancelled {
				return "REQUIRES_INSPECTION", "adapter_rejected", "duplicate_cancelled"
			}
			// AEAT reports the existing state without its fingerprint. The
			// current request may have been regenerated after a timeout.
			return "REQUIRES_INSPECTION", "adapter_rejected", "duplicate_unverified"
		}
		if err := line.Error(); err != nil {
			if errors.Is(err, verifactu.ErrWarning) {
				continue
			}
			return "INVALID", "adapter_rejected", safeErrorCode(line.Code, "adapter_rejected")
		}
	}
	return "", "", ""
}

func duplicateContents(response *verifactu.InvoiceResponse) map[string]any {
	if response == nil {
		return nil
	}
	if len(response.Lines) == 0 || response.Lines[0] == nil {
		return nil
	}
	line := response.Lines[0]
	if line.Duplicated == nil {
		return nil
	}
	payload := map[string]any{"duplicate_state": strings.TrimSpace(line.Duplicated.Status)}
	if strings.TrimSpace(line.Duplicated.Code) != "" {
		payload["code"] = safeErrorCode(line.Duplicated.Code, line.Duplicated.Code)
	}
	return payload
}

func (b laneWorkerResultBuilder) fromError(err error) laneWorkerResult {
	if errors.Is(err, context.DeadlineExceeded) || os.IsTimeout(err) {
		return b.pending(
			"adapter_temporarily_unavailable",
			"authority_timeout",
			"adapter_temporarily_unavailable",
			defaultLaneWorkerRetryAfter,
		)
	}
	var vfErr *verifactu.Error
	if errors.As(err, &vfErr) {
		if status, ok := httpStatusFromError(vfErr); ok {
			category := "adapter_temporarily_unavailable"
			if status == http.StatusTooManyRequests {
				category = "adapter_rate_limited"
			}
			return b.pending(
				category,
				fmt.Sprintf("http_%d", status),
				category,
				defaultLaneWorkerRetryAfter,
			)
		}
		if errors.Is(err, verifactu.ErrConnection) || errors.Is(err, verifactu.ErrServer) {
			return b.pending(
				"adapter_temporarily_unavailable",
				safeErrorCode(vfErr.Code(), "authority_connection"),
				"adapter_temporarily_unavailable",
				defaultLaneWorkerRetryAfter,
			)
		}
		if errors.Is(err, verifactu.ErrValidation) {
			return b.nonRetryable(
				"REQUIRES_INSPECTION",
				"authority_technical_schema_fault",
				safeErrorCode(vfErr.Code(), "authority_technical_schema_fault"),
			)
		}
		if errors.Is(err, verifactu.ErrDuplicate) {
			return b.nonRetryable("REQUIRES_INSPECTION", "adapter_rejected", "duplicate_unverified")
		}
		return b.nonRetryable(
			"INVALID",
			"adapter_rejected",
			safeErrorCode(vfErr.Code(), "adapter_rejected"),
		)
	}
	return b.pending(
		"adapter_temporarily_unavailable",
		"authority_connection",
		"adapter_temporarily_unavailable",
		defaultLaneWorkerRetryAfter,
	)
}

func (b laneWorkerResultBuilder) invalid(err error) laneWorkerResult {
	var vfErr *verifactu.Error
	if errors.As(err, &vfErr) {
		return b.nonRetryable("INVALID", "adapter_rejected", safeErrorCode(vfErr.Code(), "adapter_rejected"))
	}
	return b.nonRetryable("INVALID", "adapter_rejected", "adapter_rejected")
}

func (b laneWorkerResultBuilder) pending(
	errorCategory string,
	errorCode string,
	publicState string,
	retryAfterSeconds int,
) laneWorkerResult {
	if retryAfterSeconds <= 0 {
		retryAfterSeconds = defaultLaneWorkerRetryAfter
	}
	_ = publicState
	result := b.result("LANE_WORKER_JOB_PENDING")
	result.Retry = &laneWorkerRetry{AfterSeconds: retryAfterSeconds}
	result.Error = &laneWorkerError{Category: errorCategory, Code: errorCode}
	return result
}

func (b laneWorkerResultBuilder) nonRetryable(
	authorityState string,
	errorCategory string,
	errorCode string,
) laneWorkerResult {
	result := b.result(authorityState)
	result.Error = &laneWorkerError{Category: errorCategory, Code: errorCode}
	return result
}

func httpStatusFromError(err *verifactu.Error) (int, bool) {
	status, parseErr := strconv.Atoi(strings.TrimSpace(err.Code()))
	if parseErr != nil {
		return 0, false
	}
	switch status {
	case http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return status, true
	default:
		return status, false
	}
}

func safeErrorCode(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	var builder strings.Builder
	lastUnderscore := false
	for _, char := range strings.ToLower(value) {
		switch {
		case char >= 'a' && char <= 'z':
			builder.WriteRune(char)
			lastUnderscore = false
		case char >= '0' && char <= '9':
			builder.WriteRune(char)
			lastUnderscore = false
		default:
			if !lastUnderscore {
				builder.WriteRune('_')
				lastUnderscore = true
			}
		}
	}
	normalized := strings.Trim(builder.String(), "_")
	if normalized == "" {
		return fallback
	}
	if len(normalized) > 64 {
		return normalized[:64]
	}
	return normalized
}

func writeGatewayResult(output io.Writer, result laneWorkerResult) error {
	encoder := json.NewEncoder(output)
	return encoder.Encode(result)
}

func normalizedExecutionMode(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return executionModeDeterministic
	}
	return value
}

func normalizedOperationType(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}

func validateOperationType(value string) error {
	switch value {
	case operationTypeRegister, operationTypeCancel:
		return nil
	case "":
		return fmt.Errorf("AEAT VERI*FACTU operation type is required")
	default:
		return fmt.Errorf("unsupported AEAT VERI*FACTU operation type")
	}
}

func intEnv(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func privateArtifact(mediaType string, body []byte) *laneWorkerPrivateArtifact {
	return &laneWorkerPrivateArtifact{
		Type: mediaType,
		B64:  base64.StdEncoding.EncodeToString(body),
	}
}
