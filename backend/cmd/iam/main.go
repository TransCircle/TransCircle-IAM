// Command iam is the single binary for the TransCircle IAM backend.
//
//	iam serve        run the HTTP server
//	iam migrate      apply database migrations and exit
//	iam bootstrap    initialize keys + system data + first admin and exit
//	iam healthcheck  probe local readiness (for container HEALTHCHECK)
//	iam admin ...    offline break-glass operations (e.g. reset-mfa)
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/transcircle/iam/internal/app"
)

func main() {
	// Top-level recovery so even an unexpected panic (e.g. a catastrophic RNG
	// failure inside a CLI path) exits cleanly with a non-zero code instead of
	// dumping a stack — honoring the no-panic discipline outside the HTTP server.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "iam: fatal: %v\n", r)
			os.Exit(1)
		}
	}()

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "serve":
		err = app.Serve(ctx)
	case "migrate":
		err = app.MigrateOnly(ctx)
	case "bootstrap":
		err = app.Bootstrap(ctx)
	case "healthcheck":
		err = app.Healthcheck(ctx)
	case "admin":
		err = app.Admin(ctx, os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "iam %s: %v\n", os.Args[1], err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `TransCircle IAM
usage: iam <command>

commands:
  serve        run the HTTP server
  migrate      apply database migrations and exit
  bootstrap    initialize keys, system data, and the first admin, then exit
  healthcheck  probe local readiness
  admin <op>   offline break-glass operations:
                 reset-password <user> [pw]   reset a user's password
                 reset-mfa <user>             clear a user's MFA factors
                 grant-super-admin <user>     grant the super_admin role
`)
}
