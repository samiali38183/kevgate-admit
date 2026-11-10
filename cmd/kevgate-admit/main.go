// Command kevgate-admit is a Kubernetes validating admission webhook that
// blocks workloads based on KEV-prioritized vulnerability evidence.
package main

import (
	"os"

	"github.com/samiali38183/kevgate-admit/internal/app"
)

func main() {
	ctx, stop := app.SignalContext()
	code := app.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
