package imagesigning

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/go-logr/logr"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"

	securityv1alpha1 "github.com/kabanero-io/kabanero-security/signing-operator/pkg/apis/security/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	//	machineconfigv1 "github.com/kabanero-io/kabanero-security/signing-operator/pkg/apis/machineconfiguration.openshift.io/v1"
)

const (
	secretName    = "signature-secret-key"
	secretKeyName = "secret.asc"
	registryName  = "registry"
)

// return a secret which stores private key for signing.
func findSecret(r *ReconcileImageSigning, ns string) (*corev1.Secret, error) {
	sl := corev1.SecretList{}
	err := r.client.List(context.Background(), &sl, client.InNamespace(ns))
	if err != nil {
		return nil, err
	}
	for _, _s := range sl.Items {
		if _s.ObjectMeta.Name == secretName {
			return &_s, nil
		}
	}
	return nil, nil
}

func isKeyModified(cr *securityv1alpha1.ImageSigning, reqLogger logr.Logger) bool {
	if cr == nil {
		return false
	}
	if cr.Status.Generated {
		if cr.Spec.Identity != nil {
			// identity is set.
			id, err := getIdentity(&cr.Status.Keypair.SecretKey)
			if err != nil {
				// if there is an error, return true to force to recreate key.
				return true
			}
			reqLogger.Info("TOSHI : KEY current :   Name : " + cr.Spec.Identity.Name + ", Email : " + cr.Spec.Identity.Email + ", Comment : " + cr.Spec.Identity.Comment)
			reqLogger.Info("TOSHI : KEY generated : Name : " + id.Name + ", Email : " + id.Email + ", Comment : " + id.Comment)
			reqLogger.Info("TOSHI : KEY comp: Name : " + strconv.FormatBool(id.Name == cr.Spec.Identity.Name) + ", Email : " + strconv.FormatBool(id.Email == cr.Spec.Identity.Email) + ", Comment : " + strconv.FormatBool(id.Comment == cr.Spec.Identity.Comment))

			//return !reflect.DeepEqual(cr.Spec.Identity, &id)
			return !(*cr.Spec.Identity == *id)
		} else if cr.Spec.Keypair != nil {
			// keypair is set.
			return !reflect.DeepEqual(cr.Spec.Keypair, cr.Status.Keypair)
		}
	}
	return true
}

// return ImageSigning CR instance
// If there is only one, return it.
// If there are multiple instances exist, return the one which currently using.
// It can be found by examining Generated field in ImageSigningStatus.
// If there is not the one which has Generated flag, then it's an error condition
// since it cannot determine which one should use.
func findCR(r *ReconcileImageSigning, ns string) (*securityv1alpha1.ImageSigning, error) {
	cr := securityv1alpha1.ImageSigningList{}
	err := r.client.List(context.Background(), &cr, client.InNamespace(ns))
	if err != nil {
		return nil, err
	}
	if items := len(cr.Items); items == 0 {
		return nil, nil
	} else if items == 1 {
		return &cr.Items[0], nil
	}
	// if there are multiple, return the one of which status shows generated.
	for _, _cr := range cr.Items {
		if _cr.Status.Generated {
			return &_cr, nil
		}
	}
	return nil, errors.New("more than one ImageSigning CRs found")
}

//TODO: not used. delete later.
func getNewIdentity(id *securityv1alpha1.SignatureIdentity) string {
	comment := id.Comment
	if len(comment) > 0 {
		return fmt.Sprintf("%s (%s) <%s>", id.Name, comment, id.Email)
	}
	return fmt.Sprintf("%s <%s>", id.Name, id.Email)

}

// TODO support validating and creating image from supplied public and private key.
// TODO will be deleted
func genKey(id *securityv1alpha1.SignatureIdentity, reqLogger logr.Logger) (*openpgp.Entity, error) {
	name := id.Name
	reqLogger.Info("name is " + name)
	var e *openpgp.Entity
	e, err := openpgp.NewEntity(name, id.Comment, id.Email, nil)
	if err != nil {
		reqLogger.Error(err, "Failed to generate RSA key for signing.")
		return nil, err
	}
	// remove default subkey which is not used.
	e.Subkeys = nil
	return e, nil

}

// generate or copy keypair in the ImageSiginingSpec to ImageSigningStatus
func generateKeyPair(spec *securityv1alpha1.ImageSigningSpec, status *securityv1alpha1.ImageSigningStatus, reqLogger logr.Logger) error {
	if spec.Keypair != nil {
		// if keypair is supplied, validate the keys and set them.
		// TODO: add validation. make sure that nil check is required.
		// err := errors.New("secretKey and publicKey should be set for importing keypair.")
		reqLogger.Info("Importing RSA keypair for image signing.")
		status.Keypair = spec.Keypair
		status.ErrorMessage = ""
		status.Generated = true
		return nil
	}

	if spec.Identity != nil {
		reqLogger.Info("Generating RSA keypair for image signing.")
		var e *openpgp.Entity
		e, err := genKey(spec.Identity, reqLogger)
		if err != nil {
			status.ErrorMessage = err.Error()
			status.Generated = false
			status.Keypair.PublicKey = ""
			status.Keypair.SecretKey = ""
			return err
		}
		err = copyToStatus(e, status, reqLogger)
		if err != nil {
			status.ErrorMessage = err.Error()
			status.Generated = false
			status.Keypair.PublicKey = ""
			status.Keypair.SecretKey = ""
			return err
		}
		status.ErrorMessage = ""
		status.Generated = true
		return nil
	}
	msg := "There is not sufficient information for generating or importing RSA keypair."
	reqLogger.Info(msg)
	status.ErrorMessage = msg
	status.Generated = false
	return nil
}

func copyToStatus(e *openpgp.Entity, status *securityv1alpha1.ImageSigningStatus, reqLogger logr.Logger) error {
	sbuf := bytes.NewBuffer(nil)
	ws, err := armor.Encode(sbuf, openpgp.PrivateKeyType, nil)
	if err != nil {
		reqLogger.Error(err, "Failed to armor RSA secret key for signing.")
		return err
	}
	err = e.SerializePrivate(ws, nil)
	ws.Close()
	if err != nil {
		reqLogger.Error(err, "Failed to serialize RSA secret key for signing.")
		return err
	}
	var keypair securityv1alpha1.SignatureKeypair
	keypair.SecretKey = sbuf.String()

	pbuf := bytes.NewBuffer(nil)
	wp, err := armor.Encode(pbuf, openpgp.PublicKeyType, nil)
	if err != nil {
		reqLogger.Error(err, "Failed to armor RSA public key for signing.")
		return err
	}
	err = e.Serialize(wp)
	wp.Close()
	if err != nil {
		reqLogger.Error(err, "Failed to serialize RSA public key for signing.")
		return err
	}
	keypair.PublicKey = pbuf.String()
	status.Keypair = &keypair
	return nil
}

// create a secret named signature-secret-key which contains two elements.
// secret.asc is a secret key which will be used for signing the images.
// registry is a registry name for signature.
func createSecret(namespace *string, registry *string, armoredPrivateKey *string) (*corev1.Secret, error) {
	m := map[string][]byte{}
	m[secretKeyName] = []byte(*armoredPrivateKey)
	m[registryName] = []byte(*registry)
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: *namespace,
		},
		Data: m,
	}, nil
}

// create a secret named signature-secret-key which contains two elements.
// secret.asc is a secret key which will be used for signing the images.
// registry is a registry name for signature.
func updateSecret(secret *corev1.Secret, registry *string, armoredPrivateKey *string, reqLogger logr.Logger) bool {
	var updated bool
	registryData := []byte(*registry)
	if bytes.Compare(secret.Data[registryName], registryData) != 0 {
		secret.Data[registryName] = registryData
		reqLogger.Info("Toshi: update registry")
		updated = true
	}
	keyData := []byte(*armoredPrivateKey)
	if bytes.Compare(secret.Data[secretKeyName], keyData) != 0 {
		secret.Data[secretKeyName] = keyData
		reqLogger.Info("Toshi: update secret key")
		updated = true
	}
	return updated
}

func isOwned(secret *corev1.Secret, uid types.UID) bool {
	owner := secret.GetOwnerReferences()
	if owner != nil {
		if owner[0].UID == uid {
			return true
		}
	}
	return false
}
func getIdentity(secretKey *string) (*securityv1alpha1.SignatureIdentity, error) {
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

func parseIdentity(user *openpgp.Identity) *securityv1alpha1.SignatureIdentity {
	return &securityv1alpha1.SignatureIdentity{
		Name:    user.UserId.Name,
		Comment: user.UserId.Comment,
		Email:   user.UserId.Email,
	}
}

// By convention, this takes the form "Full Name (Comment) <email@example.com>"
func parseIdentityOld(name string) *securityv1alpha1.SignatureIdentity {
	var id securityv1alpha1.SignatureIdentity
	if strings.Contains(name, "(") {
		slices := strings.Split(name, "(")
		id.Name = strings.TrimSpace(slices[0])
		slices = strings.Split(slices[1], ")")
		id.Comment = strings.TrimSpace(slices[0])
		id.Email = strings.TrimSpace(strings.Trim(strings.Trim(strings.TrimSpace(slices[1]), "<"), ">"))
	} else {
		id.Comment = ""
		slices := strings.Split(name, "<")
		id.Name = strings.TrimSpace(slices[0])
		slices = strings.Split(slices[1], ">")
		id.Email = strings.TrimSpace(slices[0])
	}
	return &id
}
