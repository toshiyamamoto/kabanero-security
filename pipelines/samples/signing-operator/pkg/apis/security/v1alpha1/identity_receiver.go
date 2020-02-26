package v1alpha1

import (
	"bytes"
	"errors"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

// generateEntity generates Entity by using openPGP
func (id *SignatureIdentity) generateEntity() (*openpgp.Entity, error) {
	e, err := openpgp.NewEntity(id.Name, id.Comment, id.Email, nil)
	if err != nil {
		return nil, err
	}
	// remove default subkey which is not used.
	e.Subkeys = nil
	return e, nil
}

func generateSecretKey(entity *openpgp.Entity) (string, error) {
	buf := bytes.NewBuffer(nil)
	ws, err := armor.Encode(buf, openpgp.PrivateKeyType, nil)
	if err == nil {
		err = entity.SerializePrivate(ws, nil)
		ws.Close()
		if err == nil {
			return buf.String(), nil
		}
	}
	return "", err
}

func generatePublicKey(entity *openpgp.Entity) (string, error) {
	buf := bytes.NewBuffer(nil)
	ws, err := armor.Encode(buf, openpgp.PublicKeyType, nil)
	if err == nil {
		err = entity.Serialize(ws)
		ws.Close()
		if err == nil {
			return buf.String(), nil
		}
	}
	return "", err
}

func getIdentity(secretKey *string) (*SignatureIdentity, error) {
	block, err := armor.Decode(bytes.NewReader([]byte(*secretKey)))
	if err != nil {
		return nil, err
	}
	entity, err := openpgp.ReadEntity(packet.NewReader(block.Body))
	if err != nil {
		return nil, err
	}

	if len(entity.Identities) != 1 {
		return nil, errors.New("more than one identities")
	}
	var id *openpgp.Identity
	for _, _id := range entity.Identities {
		id = _id
		break
	}
	return parseIdentity(id), nil
}

func parseIdentity(user *openpgp.Identity) *SignatureIdentity {
	return &SignatureIdentity{
		Name:    user.UserId.Name,
		Comment: user.UserId.Comment,
		Email:   user.UserId.Email,
	}
}
