package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	verifactu "github.com/invopop/gobl.es.verifactu"
)

func TestGatewayCommandReadsGoblEnvelopeFromStdinAndEmitsLaneWorkerResult(t *testing.T) {
	t.Setenv(envLaneWorkerOperationID, "plz_fiscalization_job_cmd")
	t.Setenv(envAeatOperationType, operationTypeRegister)
	t.Setenv(envLaneWorkerExecutionMode, executionModeDeterministic)
	setSoftwareEnvironment(t)

	stdin := mustReadFile(t, "../../test/data/inv-base.json")
	if strings.Contains(stdin, "plz_fiscalization_job_cmd") {
		t.Fatal("test fixture unexpectedly carries operation id in stdin")
	}
	stdout := executeGatewayCommand(t, stdin)
	result := decodeLaneWorkerResult(t, stdout)
	head := laneWorkerResultHeadPayload(t, result)

	if head["contract"] != laneWorkerResultContractVersion {
		t.Fatalf("unexpected contract version: %#v", result)
	}
	if head["id"] != "plz_fiscalization_job_cmd" {
		t.Fatalf("operation id was not taken from execution settings: %#v", result)
	}
	if head["status"] != "PENDING" {
		t.Fatalf("unexpected capture state: %#v", result)
	}
	if _, ok := result["retry"]; ok {
		t.Fatalf("capture result carried an inferable retry delay: %#v", result)
	}
	chain, ok := result["chain"].(map[string]any)
	if !ok {
		t.Fatalf("capture result did not include public verification: %#v", result)
	}
	if chain["qr_provider"] != "verifactu-qr" {
		t.Fatalf("capture result did not preserve the GOBL QR provider: %#v", chain)
	}
	qrPayload, ok := chain["qr_payload"].(string)
	if !ok || !strings.HasPrefix(qrPayload, "https://prewww2.aeat.es/") {
		t.Fatalf("capture result did not preserve the GOBL QR payload: %#v", chain)
	}
	artifacts, ok := result["artifacts"].([]any)
	if !ok || len(artifacts) != 1 {
		t.Fatalf("capture result did not include request and hash-chain evidence: %#v", result)
	}
	artifact, ok := artifacts[0].(map[string]any)
	if !ok {
		t.Fatalf("evidence artifact is not an object: %#v", artifacts[0])
	}
	private, ok := artifact["private"].(map[string]any)
	if !ok || private["b64"] == "" {
		t.Fatalf("private capture evidence was not carried: %#v", artifact)
	}
	assertNoRawAuthorityLeakage(t, map[string]any{
		"contents": artifact["contents"],
		"chain":    result["chain"],
	})
}

func TestGatewayCommandBuildsCancellationWhenOperationTypeIsCancel(t *testing.T) {
	t.Setenv(envLaneWorkerOperationID, "plz_fiscalization_job_cmd")
	t.Setenv(envAeatOperationType, operationTypeCancel)
	t.Setenv(envLaneWorkerExecutionMode, executionModeDeterministic)
	setSoftwareEnvironment(t)

	stdout := executeGatewayCommand(t, mustReadFile(t, "../../test/data/inv-base.json"))
	result := decodeLaneWorkerResult(t, stdout)

	artifacts, ok := result["artifacts"].([]any)
	if !ok || len(artifacts) != 1 {
		t.Fatalf("cancellation capture did not include request and hash-chain evidence: %#v", result)
	}
	requestArtifact := artifacts[0].(map[string]any)
	content := requestArtifact["contents"].(map[string]any)
	if content["operation_type"] != operationTypeCancel {
		t.Fatalf("cancellation operation type was not exposed: %#v", content)
	}
	privateXML := decodedPrivateEvidence(t, requestArtifact)
	if !strings.Contains(privateXML, "RegistroAnulacion") {
		t.Fatalf("cancellation request did not use RegistroAnulacion: %s", privateXML)
	}
	if strings.Contains(privateXML, "RegistroAlta") {
		t.Fatalf("cancellation request unexpectedly used RegistroAlta: %s", privateXML)
	}
	assertNoRawAuthorityLeakage(t, result)
}

func TestGatewayCommandRejectsInvalidEnvelopeAsClosedResult(t *testing.T) {
	t.Setenv(envLaneWorkerOperationID, "plz_fiscalization_job_cmd")
	t.Setenv(envAeatOperationType, operationTypeRegister)
	t.Setenv(envLaneWorkerExecutionMode, executionModeDeterministic)
	setSoftwareEnvironment(t)

	stdout := executeGatewayCommand(t, "{not-json")
	result := decodeLaneWorkerResult(t, stdout)
	head := laneWorkerResultHeadPayload(t, result)

	if head["status"] != "INVALID" {
		t.Fatalf("invalid envelope did not fail closed: %#v", result)
	}
	if result["retry"] != nil {
		t.Fatalf("invalid envelope should not be retryable: %#v", result)
	}
	resultError := laneWorkerResultError(t, result)
	if resultError["category"] != "adapter_rejected" {
		t.Fatalf("invalid envelope category = %#v", resultError["category"])
	}
	if resultError["code"] != "adapter_rejected" {
		t.Fatalf("invalid envelope code = %#v", resultError["code"])
	}
}

func TestGatewayOwnsDERFlagsWithoutWideningOtherCommands(t *testing.T) {
	command := root().cmd()

	gatewayCommand, _, err := command.Find([]string{"gateway"})
	if err != nil {
		t.Fatal(err)
	}
	if gatewayCommand.Flags().Lookup("cert-der") == nil {
		t.Fatal("gateway command must accept DER certificate execution setting")
	}
	if gatewayCommand.Flags().Lookup("key-der") == nil {
		t.Fatal("gateway command must accept DER private key execution setting")
	}

	for _, name := range []string{"send", "cancel", "convert"} {
		laneCommand, _, err := command.Find([]string{name})
		if err != nil {
			t.Fatal(err)
		}
		if laneCommand.Flags().Lookup("cert-der") != nil {
			t.Fatalf("%s command leaked gateway DER certificate flag", name)
		}
		if laneCommand.Flags().Lookup("key-der") != nil {
			t.Fatalf("%s command leaked gateway DER private key flag", name)
		}
	}
}

func TestLaneWorkerTraceCarrierKeepsOnlyW3CContext(t *testing.T) {
	t.Setenv(envTraceparent, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	t.Setenv(envTracestate, "plazia=unit")
	t.Setenv("CERTIFICATE_PRIVATE_KEY_DER_PATH", "/private/key.der")

	carrier := laneWorkerTraceCarrierFromEnvironment()

	if carrier["traceparent"] != "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01" {
		t.Fatalf("traceparent was not carried: %#v", carrier)
	}
	if carrier["tracestate"] != "plazia=unit" {
		t.Fatalf("tracestate was not carried: %#v", carrier)
	}
	if len(carrier) != 2 {
		t.Fatalf("private lane worker material leaked into trace carrier: %#v", carrier)
	}
}

func TestLaneWorkerResultFromErrorMapsFaultTimeoutAndBackpressureSafely(t *testing.T) {
	cases := []struct {
		name          string
		err           error
		authority     string
		errorCategory string
		errorCode     string
		retryable     bool
	}{
		{
			name:          "soap fault",
			err:           verifactu.ErrValidation.WithCode("soap:Client").WithMessage("<soapenv:Fault><faultstring>bad</faultstring></soapenv:Fault>"),
			authority:     "REQUIRES_INSPECTION",
			errorCategory: "authority_technical_schema_fault",
			errorCode:     "soap_client",
		},
		{
			name: "numeric SOAP fault",
			err: (&verifactu.Fault{
				Code: "soap:Client", Message: "Codigo[4104].Error en la cabecera",
			}).Err(),
			authority: "REQUIRES_INSPECTION", errorCategory: "authority_technical_schema_fault", errorCode: "4104",
		},
		{
			name: "server fault",
			err: (&verifactu.Fault{
				Code: "soap:Server", Message: "Servicio no disponible",
			}).Err(),
			authority: "LANE_WORKER_JOB_PENDING", errorCategory: "adapter_temporarily_unavailable",
			errorCode: "authority_connection", retryable: true,
		},
		{
			name: "duplicate without a response line", err: verifactu.ErrDuplicate,
			authority: "REQUIRES_INSPECTION", errorCategory: "adapter_rejected", errorCode: "duplicate_unverified",
		},
		{
			name:          "timeout",
			err:           context.DeadlineExceeded,
			authority:     "LANE_WORKER_JOB_PENDING",
			errorCategory: "adapter_temporarily_unavailable",
			errorCode:     "authority_timeout",
			retryable:     true,
		},
		{
			name:          "rate limit",
			err:           verifactu.ErrValidation.WithCode("429").WithMessage("too many requests"),
			authority:     "LANE_WORKER_JOB_PENDING",
			errorCategory: "adapter_rate_limited",
			errorCode:     "http_429",
			retryable:     true,
		},
		{
			name:          "service unavailable",
			err:           verifactu.ErrValidation.WithCode("503").WithMessage("<xml>unavailable</xml>"),
			authority:     "LANE_WORKER_JOB_PENDING",
			errorCategory: "adapter_temporarily_unavailable",
			errorCode:     "http_503",
			retryable:     true,
		},
		{
			name:          "gateway timeout",
			err:           verifactu.ErrValidation.WithCode("504").WithMessage("gateway timeout"),
			authority:     "LANE_WORKER_JOB_PENDING",
			errorCategory: "adapter_temporarily_unavailable",
			errorCode:     "http_504",
			retryable:     true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := laneWorkerResults("plz_fiscalization_job_cmd").fromError(tc.err)

			if result.Head.Status != tc.authority {
				t.Fatalf("authority state = %s", result.Head.Status)
			}
			if result.Error == nil || result.Error.Category != tc.errorCategory {
				t.Fatalf("error category = %#v", result.Error)
			}
			if result.Error == nil || result.Error.Code != tc.errorCode {
				t.Fatalf("error code = %#v", result.Error)
			}
			if tc.retryable && (result.Retry == nil || result.Retry.AfterSeconds <= 0) {
				t.Fatalf("retryable result did not carry retry delay: %#v", result)
			}
			assertNoRawAuthorityLeakage(t, result)
		})
	}
}

func TestLaneWorkerResultFromErrorKeepsTransportErrorsRetryable(t *testing.T) {
	result := laneWorkerResults("plz_fiscalization_job_cmd").fromError(
		errors.New("dial tcp: connection refused"),
	)

	if result.Head.Status != "LANE_WORKER_JOB_PENDING" {
		t.Fatalf("authority state = %s", result.Head.Status)
	}
	if result.Error == nil || result.Error.Category != "adapter_temporarily_unavailable" {
		t.Fatalf("error category = %#v", result.Error)
	}
	if result.Error == nil || result.Error.Code != "authority_connection" {
		t.Fatalf("error code = %#v", result.Error)
	}
	if result.Retry == nil || result.Retry.AfterSeconds <= 0 {
		t.Fatalf("transport error did not carry retry delay: %#v", result)
	}
	assertNoRawAuthorityLeakage(t, result)
}

func executeGatewayCommand(t *testing.T, stdin string) string {
	t.Helper()

	command := root().cmd()
	command.SetArgs([]string{"gateway"})
	command.SetIn(strings.NewReader(stdin))
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	if err := command.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("gateway command failed: %v: %s", err, stderr.String())
	}
	return stdout.String()
}

func decodeLaneWorkerResult(t *testing.T, body string) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("result was not JSON: %v\n%s", err, body)
	}
	return result
}

func laneWorkerResultHeadPayload(t *testing.T, result map[string]any) map[string]any {
	t.Helper()
	head, ok := result["head"].(map[string]any)
	if !ok {
		t.Fatalf("lane worker result missing head: %#v", result)
	}
	return head
}

func laneWorkerResultError(t *testing.T, result map[string]any) map[string]any {
	t.Helper()
	resultError, ok := result["error"].(map[string]any)
	if !ok {
		t.Fatalf("lane worker result missing error: %#v", result)
	}
	return resultError
}

func setSoftwareEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("SOFTWARE_COMPANY_NIF", "B12345678")
	t.Setenv("SOFTWARE_COMPANY_NAME", "Plazia Fiscal Engine")
	t.Setenv("SOFTWARE_NAME", "Plazia Fiscal Engine")
	t.Setenv("SOFTWARE_VERSION", "0.1.0")
	t.Setenv("SOFTWARE_ID_SISTEMA_INFORMATICO", "01")
	t.Setenv("SOFTWARE_NUMERO_INSTALACION", "plz_system_cmd")
}

func assertNoRawAuthorityLeakage(t *testing.T, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	serialized := strings.ToLower(string(body))
	for _, forbidden := range []string{
		"<soap",
		"<xml",
		"faultstring",
		"regfactusistemafacturacion",
		"respuestaregfactusistemafacturacion",
		"soap_fault",
		"xml_base64",
	} {
		if strings.Contains(serialized, forbidden) {
			t.Fatalf("raw authority data leaked %s through %s", forbidden, serialized)
		}
	}
}

func decodedPrivateEvidence(t *testing.T, artifact map[string]any) string {
	t.Helper()
	private, ok := artifact["private"].(map[string]any)
	if !ok {
		t.Fatalf("artifact did not carry private evidence: %#v", artifact)
	}
	encoded, ok := private["b64"].(string)
	if !ok || encoded == "" {
		t.Fatalf("artifact did not carry private evidence: %#v", artifact)
	}
	body, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("private evidence was not base64: %v", err)
	}
	return string(body)
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestPreviousChainDataRejectsIncompletePayload(t *testing.T) {
	_, err := previousChainDataFromJSON(`{"issuer":"B12345678"}`)
	if err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("unexpected previous chain error: %v", err)
	}
}
