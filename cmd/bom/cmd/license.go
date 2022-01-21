/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"sigs.k8s.io/bom/pkg/spdx"
)

type licenseOptions struct {
	Format string //
}

var licenseOpts = &licenseOptions{}

var licenseCmd = &cobra.Command{
	Short: "bom document license → Get licensing information from an SBOM",
	Long: `bom document license → Get licensing information from an SBOM",

TBD

`,
	Use:               "license",
	SilenceUsage:      true,
	SilenceErrors:     true,
	PersistentPreRunE: initLogging,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return errors.New("At least one spdx sbom should be specified")
		}
		return runLicense(licenseOpts, args)
	},
}

func init() {
	licenseCmd.PersistentFlags().StringVar(
		&licenseOpts.Format,
		"format",
		"table",
		"Output format for licensing data. Can be either table or json",
	)
}

func runLicense(opts *licenseOptions, args []string) error {
	doc, err := spdx.OpenDoc(args[0])
	if err != nil {
		return errors.Wrap(err, "opening doc")
	}

	if opts.Format == "table" {
		fmt.Println(spdx.Banner())
		return licenseTable(opts, doc)
	}
	return errors.New("Unknown format")
}

func licenseTable(_ *licenseOptions, doc *spdx.Document) error {
	sbomData, err := doc.LicenseData()
	if err != nil {
		return errors.Wrap(err, "getting license information")
	}

	data := [][]string{}

	for _, packageData := range sbomData.Packages {
		data = append(data, []string{
			packageData.Name,
			packageData.ID,
			strings.Join(packageData.LicenseConcluded, " + "),
			fmt.Sprintf("%d", packageData.NumDependencies),
			fmt.Sprintf("%d", packageData.NumLicenses),
		},
		)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"Package", "SPDX ID", "License", "Dependencies", "Num Licenses"})
	table.SetBorder(true)
	table.AppendBulk(data)
	table.Render()
	return nil
}
