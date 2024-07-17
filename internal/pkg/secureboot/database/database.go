// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package database generates SecureBoot auto-enrollment database.
package database

import (
	"crypto/sha256"
	"crypto/x509"
	"embed"

	"github.com/foxboron/go-uefi/efi"
	"github.com/foxboron/go-uefi/efi/signature"
	"github.com/foxboron/go-uefi/efi/util"
	"github.com/google/uuid"

	"github.com/siderolabs/talos/internal/pkg/secureboot/pesign"
	"github.com/siderolabs/talos/pkg/machinery/constants"
)

// Entry is a UEFI database entry.
type Entry struct {
	Name     string
	Contents []byte
}

const (
	microsoftSignatureOwnerGUID = "77fa9abd-0359-4d32-bd60-28f4e78f784b"
)

// Well-known UEFI certificates (DER data).
//
//go:embed certs/*
var certificatesData embed.FS

// Well-known Microsoft UEFI DB certificates.
// ref: https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance?view=windows-11#14-signature-databases-db-and-dbx
var microsoftUEFIDBCertificates []*x509.Certificate

// Well-known Microsoft UEFI KEK certificates.
// ref: https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance?view=windows-11#14-signature-databases-db-and-dbx
var microsoftUEFIKEKCertificates []*x509.Certificate

func init() {
	for _, n := range []string{
		// "MicWinProPCA2011_2011-10-19.crt",
		// "windows uefi ca 2023.crt",
		"MicCorUEFCA2011_2011-06-27.crt",
		"microsoft uefi ca 2023.crt",
	} {
		data, err := certificatesData.ReadFile("certs/" + n)
		if err != nil {
			panic(err)
		}

		certs, err := x509.ParseCertificates(data)
		if err != nil {
			panic(err)
		}

		microsoftUEFIDBCertificates = append(microsoftUEFIDBCertificates, certs...)
	}

	for _, n := range []string{
		"MicCorKEKCA2011_2011-06-24.crt",
		"microsoft corporation kek 2k ca 2023.crt",
	} {
		data, err := certificatesData.ReadFile("certs/" + n)
		if err != nil {
			panic(err)
		}

		certs, err := x509.ParseCertificates(data)
		if err != nil {
			panic(err)
		}

		microsoftUEFIKEKCertificates = append(microsoftUEFIKEKCertificates, certs...)
	}
}

// Generate generates a UEFI database to enroll the signing certificate.
//
// ref: https://blog.hansenpartnership.com/the-meaning-of-all-the-uefi-keys/
//
//nolint:gocyclo
func Generate(enrolledCertificate []byte, includeMicrosoftCerts bool, signer pesign.CertificateSigner) ([]Entry, error) {
	// derive UUID from enrolled certificate
	uuid := uuid.NewHash(sha256.New(), uuid.NameSpaceX500, enrolledCertificate, 4)

	efiGUID := util.StringToGUID(uuid.String())

	// Create PK ESL
	pk := signature.NewSignatureDatabase()
	if err := pk.Append(signature.CERT_X509_GUID, *efiGUID, enrolledCertificate); err != nil {
		return nil, err
	}

	signedPK, err := efi.SignEFIVariable(signer.Signer(), signer.Certificate(), "PK", pk.Bytes())
	if err != nil {
		return nil, err
	}

	// Create KEK ESL
	kek := signature.NewSignatureDatabase()
	if err := kek.Append(signature.CERT_X509_GUID, *efiGUID, enrolledCertificate); err != nil {
		return nil, err
	}

	if includeMicrosoftCerts {
		owner := util.StringToGUID(microsoftSignatureOwnerGUID)
		for _, cert := range microsoftUEFIKEKCertificates {
			if err := kek.Append(signature.CERT_X509_GUID, *owner, cert.Raw); err != nil {
				return nil, err
			}
		}
	}

	signedKEK, err := efi.SignEFIVariable(signer.Signer(), signer.Certificate(), "KEK", kek.Bytes())
	if err != nil {
		return nil, err
	}

	// Create db ESL
	db := signature.NewSignatureDatabase()
	if err := db.Append(signature.CERT_X509_GUID, *efiGUID, enrolledCertificate); err != nil {
		return nil, err
	}

	if includeMicrosoftCerts {
		owner := util.StringToGUID(microsoftSignatureOwnerGUID)
		for _, cert := range microsoftUEFIDBCertificates {
			if err := db.Append(signature.CERT_X509_GUID, *owner, cert.Raw); err != nil {
				return nil, err
			}
		}
	}

	signedDB, err := efi.SignEFIVariable(signer.Signer(), signer.Certificate(), "db", db.Bytes())
	if err != nil {
		return nil, err
	}

	return []Entry{
		{Name: constants.SignatureKeyAsset, Contents: signedDB},
		{Name: constants.KeyExchangeKeyAsset, Contents: signedKEK},
		{Name: constants.PlatformKeyAsset, Contents: signedPK},
	}, nil
}
