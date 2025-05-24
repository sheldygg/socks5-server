package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"slices"
	"time"

	"github.com/armon/go-socks5"
	"github.com/caarlos0/env/v6"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	requestTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "socks5_requests_total",
			Help: "Total number of SOCKS5 requests",
		},
		[]string{"command", "status"},
	)

	requestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "socks5_request_duration_seconds",
			Help:    "Duration of SOCKS5 requests in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"command"},
	)

	endpointRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "socks5_endpoint_requests_total",
			Help: "Total number of requests to specific endpoints",
		},
		[]string{"host", "port"},
	)
)

type params struct {
	User            string   `env:"PROXY_USER" envDefault:""`
	Password        string   `env:"PROXY_PASSWORD" envDefault:""`
	Port            string   `env:"PROXY_PORT" envDefault:"1080"`
	AllowedDestFqdn string   `env:"ALLOWED_DEST_FQDN" envDefault:""`
	AllowedIPs      []string `env:"ALLOWED_IPS" envSeparator:"," envDefault:""`
	MetricsPort     string   `env:"METRICS_PORT" envDefault:"2112"`
}

type metricsRules struct {
	original   socks5.RuleSet
	allowedIPs []string
}

func (r *metricsRules) Allow(ctx context.Context, req *socks5.Request) (context.Context, bool) {
	start := time.Now()
	newCtx, result := r.original.Allow(ctx, req)
	duration := time.Since(start).Seconds()

	if len(r.allowedIPs) > 0 && !slices.Contains(r.allowedIPs, req.RemoteAddr.IP.String()) {
		return newCtx, false
	}

	commandType := "unknown"
	switch req.Command {
	case socks5.ConnectCommand:
		commandType = "connect"
	case socks5.BindCommand:
		commandType = "bind"
	case socks5.AssociateCommand:
		commandType = "associate"
	}

	status := "success"
	if !result {
		status = "denied"
	}

	requestTotal.WithLabelValues(commandType, status).Inc()
	requestDuration.WithLabelValues(commandType).Observe(duration)

	if result && req.Command == socks5.ConnectCommand {
		host := req.DestAddr.FQDN
		if host == "" {
			host = req.DestAddr.IP.String()
		}
		port := fmt.Sprintf("%d", req.DestAddr.Port)

		endpointRequests.WithLabelValues(host, port).Inc()
	}

	return newCtx, result
}

func main() {
	cfg := params{}
	err := env.Parse(&cfg)
	if err != nil {
		log.Printf("%+v\n", err)
	}

	conf := &socks5.Config{
		Rules: &metricsRules{
			original:   socks5.PermitAll(),
			allowedIPs: cfg.AllowedIPs,
		},
	}

	if cfg.User != "" && cfg.Password != "" {
		creds := socks5.StaticCredentials{
			cfg.User: cfg.Password,
		}
		cator := socks5.UserPassAuthenticator{Credentials: creds}
		conf.AuthMethods = []socks5.Authenticator{cator}
	}

	server, err := socks5.New(conf)
	if err != nil {
		log.Fatalf("Failed to create SOCKS5 server: %v", err)
	}

	go func() {
		http.Handle("/metrics", promhttp.Handler())
		log.Println("Starting metrics server on :" + cfg.MetricsPort)
		if err := http.ListenAndServe(":"+cfg.MetricsPort, nil); err != nil {
			log.Fatalf("Failed to start metrics server: %v", err)
		}
	}()

	log.Println("Starting SOCKS5 server on :" + cfg.Port)
	if err := server.ListenAndServe("tcp", ":"+cfg.Port); err != nil {
		log.Fatalf("Failed to start SOCKS5 server: %v", err)
	}
}
