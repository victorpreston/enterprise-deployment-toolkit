package main

import (
	"os"

	"github.com/gitpod-io/enterprise-deployment-toolkit/gitpod-network-check/cmd"
	log "github.com/sirupsen/logrus"
)

func main() {
	err := cmd.Execute()
	if err != nil {

		log.WithError(err).Fatal("error in the cli. exiting")
		os.Exit(1)
	}
}
