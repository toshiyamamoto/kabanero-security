package v1alpha1

// GetPrivateKey returns generated private key. If key does not exist, return empty string.
func (iss *ImageSigningStatus) GetPrivateKey() string {
	if iss.Keypair != nil {
		return iss.Keypair.SecretKey
	}
	return ""
}

// GetPublicKey returns generated public key. If key does not exist, return empty string.
func (iss *ImageSigningStatus) GetPublicKey() string {
	if iss.Keypair != nil {
		return iss.Keypair.PublicKey
	}
	return ""
}

// getGenerated returns Generated bool value
func (iss *ImageSigningStatus) getGenerated() bool {
	return iss.Generated
}

// setGenerated sets Generated bool value
func (iss *ImageSigningStatus) setGenerated(value bool) {
	iss.Generated = value
	return
}

// deleteKeypair deletes generated keypair, sets Generated as false, and sets specified error message.
func (iss *ImageSigningStatus) deleteGeneratedKeypair(value string) {
	iss.ErrorMessage = value
	iss.Keypair = nil
	iss.Generated = false
	return
}

// setKeypair sets specified keypair and set Generated as generatedand, ErrorMessage as empty.
func (iss *ImageSigningStatus) setKeypair(keypair *SignatureKeypair) {
	iss.Keypair = keypair
	iss.ErrorMessage = ""
	iss.Generated = true
	return
}

// SetKeypair sets specified entity and set Generated as generatedand, ErrorMessage as empty.
// If the process fails, saved the error information and set Generated as false.
// This is becuase it is unlikely that the error condtion will recover without human intervension.
func (iss *ImageSigningStatus) setIdentity(id *SignatureIdentity) {
	entity, err := id.generateEntity()
	if err == nil {
		var keypair SignatureKeypair
		keypair.SecretKey, err = generateSecretKey(entity)
		if err == nil {
			keypair.PublicKey, err = generatePublicKey(entity)
			if err == nil {
				iss.Keypair = &keypair
				iss.ErrorMessage = ""
				iss.Generated = true
				return
			}
		}
	}
	// some error happend.
	iss.Keypair = nil
	iss.ErrorMessage = err.Error()
	iss.Generated = false
	return
}
