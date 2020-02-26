package v1alpha1

// existKeypair returns whether keypair values are set.
func (issp *ImageSigningSpec) existsKeypair() bool {
	return issp.Keypair != nil && len(issp.Keypair.SecretKey) > 0 && len(issp.Keypair.PublicKey) > 0
}

// existIdentity returns whether identity values are set.
func (issp *ImageSigningSpec) existsIdentity() bool {
	return issp.Identity != nil && len(issp.Identity.Name) > 0 && len(issp.Identity.Email) > 0
}
