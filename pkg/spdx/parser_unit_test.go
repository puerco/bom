/*
Copyright 2022 The Kubernetes Authors.

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

package spdx

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDetectSBOMEncoding(t *testing.T) {
	for _, tc := range []struct {
		fragment         string
		shouldErr        bool
		expectedEncoding string
	}{
		{
			`SPDXVersion: SPDX-2.2
    DataLicense: CC0-1.0
    SPDXID: SPDXRef-DOCUMENT
    DocumentName: Tern report for nginx
    DocumentNamespace: https://spdx.org/spdxdocs/tern-report-2.10.1-nginx-5fc8720c-a097-4825-afd2-17fe2c32981c
    LicenseListVersion: 3.8
    Creator: Tool: tern-2.10.1
    Created: 2022-07-04T18:43:35Z
    DocumentComment: <text>This document was generated by the Tern Project: https://github.com/tern-tools/tern</text>

    PackageName: nginx
    SPDXID: SPDXRef-nginx-latest
    PackageVersion: latest
    PackageDownloadLocation: NOASSERTION
    FilesAnalyzed: false
    PackageLicenseConcluded: NOASSERTION
    PackageLicenseDeclared: NOASSERTION
    PackageCopyrightText: NOASSERTION
`,
			false,
			"spdx",
		},
		{
			`{
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "sbom-sha256:3b72bb7f7ce12357a17d40f5198708823333790dd20d460613a9cdaabc97bdd6",
    "spdxVersion": "SPDX-2.2",
    "creationInfo": {
      "created": "2022-07-01T02:27:39Z",
      "creators": [
        "Tool: ko (devel)"
      ]
    },
    "dataLicense": "CC0-1.0",
    "documentNamespace": "http://spdx.org/spdxdocs/kosha256:3b72bb7f7ce12357a17d40f5198708823333790dd20d460613a9cdaabc97bdd6",
    "documentDescribes": [
      "SPDXRef-Package-sha256-3b72bb7f7ce12357a17d40f5198708823333790dd20d460613a9cdaabc97bdd6"
    ],
    "packages": [
  `,
			false,
			"spdx+json",
		},
		{
			// Junk in file
			`lskjdflksjdflkjsdf`,
			false,
			"",
		},
	} {
		tmp, err := os.CreateTemp("", "")
		require.NoError(t, err)
		defer os.Remove(t.Name())
		require.NoError(t, os.WriteFile(tmp.Name(), []byte(tc.fragment), os.FileMode(0o0644)))
		format, err := DetectSBOMEncoding(tmp)
		if tc.shouldErr {
			require.Error(t, err)
		} else {
			require.Equal(t, tc.expectedEncoding, format)
		}
	}
}

func TestParseJsonInternal(t *testing.T) {
	file, err := os.Open("testdata/images.spdx.json")
	require.NoError(t, err)

	doc, err := parseJSON(file)
	require.NoError(t, err)

	require.Len(t, doc.Packages, 1)
	rootPkg, ok := doc.Packages["SPDXRef-Package-sha256C58f44417ca5eae5c4832baf4f977a12d8492bca835cdf07d44c9db210409b1ba38"]
	require.True(t, ok)
	require.Len(t, rootPkg.Relationships, 1)
	require.Equal(t, rootPkg.Relationships[0].PeerReference, "SPDXRef-Package-172.19.0.1C585000C47apko-testC64sha256C5838692af7edf0ffdb93792734e74b16d7711b4d6a91c0ecae1b390ea0b5a80c6e")
	require.Len(t, doc.ExternalDocRefs, 0)
	layerPackage, ok := rootPkg.Relationships[0].Peer.(*Package)
	require.True(t, ok)
	require.NotNil(t, layerPackage)
	rels := layerPackage.GetRelationships()
	require.Len(t, *rels, 21)
	require.Equal(t, doc.LicenseListVersion, "3.16")
	require.Equal(t, doc.Creator.Organization, "Chainguard, Inc")
	require.Equal(t, doc.Creator.Tool[0], "apko (devel)")

	require.Len(t, layerPackage.ExternalRefs, 1)
	require.Equal(t, layerPackage.ExternalRefs[0].Category, "PACKAGE_MANAGER")
	require.Equal(t, layerPackage.ExternalRefs[0].Locator, "pkg:oci/172.19.0.1:5000%2Fapko-test@sha256:38692af7edf0ffdb93792734e74b16d7711b4d6a91c0ecae1b390ea0b5a80c6e?arch=amd64\u0026tag=latest")
	require.Equal(t, layerPackage.ExternalRefs[0].Type, "purl")
}

func TestParseJsonExternal(t *testing.T) {
	file, err := os.Open("testdata/external-references.spdx.json")
	require.NoError(t, err)

	doc, err := parseJSON(file)
	require.NoError(t, err)

	rootPackage := "sha256-af1c5f9673f78aa7a575d627cd8a210bf6a895b0065f719a098dc035eee55a58"

	require.Len(t, doc.Packages, 1)
	require.Len(t, doc.Packages[rootPackage].Relationships, 2)
	require.Len(t, doc.ExternalDocRefs, 2)

	for _, rel := range doc.Packages[rootPackage].Relationships {
		if rel.PeerReference == "SPDXRef-Package-sha256-d0370905ad41c4eb2b1a56f3139fd6a9acfcef203c27e2a9e1655eab28351fd6" {
			require.Equal(t, rel.PeerExtReference, "DocumentRef-386-image-sbom:SPDXRef-Package-sha256-d0370905ad41c4eb2b1a56f3139fd6a9acfcef203c27e2a9e1655eab28351fd6")
		} else {
			require.Equal(t, rel.PeerExtReference, "DocumentRef-amd64-image-sbom:SPDXRef-Package-sha256-b09ddd04b47e07919402c15ea21bf839a95f6bf38ec0df1594c296425010cf1a")
			require.Equal(t, rel.PeerReference, "SPDXRef-Package-sha256-b09ddd04b47e07919402c15ea21bf839a95f6bf38ec0df1594c296425010cf1a")
		}
	}

	for _, eref := range doc.ExternalDocRefs {
		if eref.ID == "DocumentRef-amd64-image-sbom" {
			require.Equal(t, eref.URI, "https://172.19.0.1:5000/v2/test-nosbom2/blobs/sha256:430892ae21dd7f8174183be12a500cfc32fc48a824f1e5a88fced42b4193fd1a")
			require.Equal(t, eref.Checksums["SHA256"], "430892ae21dd7f8174183be12a500cfc32fc48a824f1e5a88fced42b4193fd1a")
		} else {
			require.Equal(t, eref.ID, "DocumentRef-386-image-sbom")
			require.Equal(t, eref.URI, "https://172.19.0.1:5000/v2/test-nosbom2/blobs/sha256:799503c8e7f1fe6a665e089780863d0f3c8d7cca64ded68c71a47544337ff983")
			require.Equal(t, eref.Checksums["SHA256"], "799503c8e7f1fe6a665e089780863d0f3c8d7cca64ded68c71a47544337ff983")
		}
	}
}
