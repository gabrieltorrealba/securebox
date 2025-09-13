package securebox

import (
	"github.com/gabrieltorrealba/securebox/aead"
	"github.com/gabrieltorrealba/securebox/kdf"
	"github.com/gabrieltorrealba/securebox/nonce"
)

// Option defines a configuration option for the Box.
type Option func(*Box)

// WithAEAD sets the AEAD implementation to use.
func WithAEAD(x aead.AEAD) Option { return func(b *Box) { b.AEAD = x } }

// WithKDF sets the KDF implementation to use.
func WithKDF(x kdf.KDF) Option { return func(b *Box) { b.KDF = x } }

// WithNonceSource sets the NonceSource implementation to use.
func WithNonceSource(ns nonce.NonceSource) Option { return func(b *Box) { b.NonceSource = ns } }

// WithPasswordValidation enables or disables password validation.
func WithPasswordValidation(v bool) Option { return func(b *Box) { b.ValidatePW = v } }
