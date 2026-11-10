package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	verifactu "github.com/invopop/gobl.es.verifactu"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const (
	envLaneWorkerOtlpTracesEndpoint = "PLZC_LANE_GATEWAY_OTLP_TRACES_ENDPOINT"
	envTraceparent                  = "TRACEPARENT"
	envTracestate                   = "TRACESTATE"

	laneWorkerTracerName  = "github.com/invopop/gobl.es.verifactu/cmd/gobl.verifactu"
	laneWorkerServiceName = "aeat_verifactu-worker"
)

var laneWorkerTracing = struct {
	sync.Once
}{}

func (c *gatewayOpts) startLaneOperationSpan(
	ctx context.Context,
	mode string,
	operationType string,
) (context.Context, trace.Span) {
	authorityEnvironment := "sandbox"
	if c.production {
		authorityEnvironment = "production"
	}
	return startLaneOperationSpan(ctx, mode, operationType, authorityEnvironment)
}

func startLaneOperationSpan(
	ctx context.Context,
	mode string,
	operationType string,
	authorityEnvironment string,
) (context.Context, trace.Span) {
	laneWorkerTracing.Do(func() {
		_, _ = setupLaneWorkerTracing(ctx)
	})
	if !trace.SpanContextFromContext(ctx).IsValid() {
		ctx = otel.GetTextMapPropagator().Extract(ctx, laneWorkerTraceCarrierFromEnvironment())
	}
	return otel.Tracer(laneWorkerTracerName).Start(
		ctx,
		"aeat.verifactu.lane_operation",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("authority.system", "aeat_verifactu"),
			attribute.String("authority.environment", authorityEnvironment),
			attribute.String("plazia.lane", "aeat_verifactu"),
			attribute.String("plazia.lane.operation", operationType),
			attribute.String("plazia.lane.mode", mode),
		),
	)
}

func setupLaneWorkerTracing(ctx context.Context) (func(context.Context) error, error) {
	otel.SetTextMapPropagator(propagation.TraceContext{})
	endpoint := strings.TrimSpace(os.Getenv(envLaneWorkerOtlpTracesEndpoint))
	if endpoint == "" {
		return func(context.Context) error { return nil }, nil
	}
	exporter, err := otlptracehttp.New(
		ctx,
		otlptracehttp.WithEndpointURL(endpoint),
	)
	if err != nil {
		return nil, err
	}
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exporter),
		sdktrace.WithResource(
			resource.NewWithAttributes(
				"",
				attribute.String("service.name", laneWorkerServiceName),
			),
		),
	)
	otel.SetTracerProvider(tracerProvider)
	return tracerProvider.Shutdown, nil
}

func laneWorkerTraceCarrierFromEnvironment() propagation.MapCarrier {
	carrier := propagation.MapCarrier{}
	if traceparent := strings.TrimSpace(os.Getenv(envTraceparent)); traceparent != "" {
		carrier["traceparent"] = traceparent
	}
	if tracestate := strings.TrimSpace(os.Getenv(envTracestate)); tracestate != "" {
		carrier["tracestate"] = tracestate
	}
	return carrier
}

func finishLaneOperationSpan(span trace.Span, result laneWorkerResult) {
	if result.Head.Status != "" {
		span.SetAttributes(attribute.String("plazia.lane.result_status", result.Head.Status))
	}
	if result.Error == nil {
		return
	}
	span.SetAttributes(attribute.String("plazia.lane.error_category", result.Error.Category))
	span.SetStatus(codes.Error, "lane worker result failed")
}

func (c *gatewayOpts) submitInvoice(
	ctx context.Context,
	client *verifactu.Client,
	request *verifactu.InvoiceRequest,
) (*verifactu.InvoiceResponse, error) {
	environment := "production"
	if client.Sandbox() {
		environment = "sandbox"
	}
	ctx, span := otel.Tracer(laneWorkerTracerName).Start(
		ctx,
		"aeat.verifactu.authority_call",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("authority.system", "aeat_verifactu"),
			attribute.String("authority.environment", environment),
			attribute.String("http.method", "POST"),
		),
	)
	defer span.End()
	response, err := c.sendInvoice(client, ctx, request)
	if err != nil {
		span.SetAttributes(attribute.String("error.type", fmt.Sprintf("%T", err)))
		span.SetStatus(codes.Error, "failed")
	}
	return response, err
}
