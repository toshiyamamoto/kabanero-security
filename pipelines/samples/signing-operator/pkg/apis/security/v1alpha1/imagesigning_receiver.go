package v1alpha1

import (
	"reflect"
	"strconv"

	corev1 "k8s.io/api/core/v1"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	finalizerName = "kabanero.io.security.signing.operator"
)

var log = logf.Log.WithName("imagesigning_receiver")

// ExistsFinalizer returns whehter the finalizer is set.
func (is *ImageSigning) ExistsFinalizer() bool {
	for _, f := range is.ObjectMeta.Finalizers {
		if f == finalizerName {
			return true
		}
	}
	return false
}

// SetFinalizer sets the finalizer. if it is set, return true.
func (is *ImageSigning) SetFinalizer() bool {
	if !is.ExistsFinalizer() {
		is.ObjectMeta.Finalizers = append(is.ObjectMeta.Finalizers, finalizerName)
		return true
	}
	return false
}

// ClearFinalizer removes the finalizer.
// client.update needs to be invoked to save the updated information.
func (is *ImageSigning) ClearFinalizer() {
	var newFinalizerList []string
	for _, f := range is.ObjectMeta.Finalizers {
		if f == finalizerName {
			continue
		}
		newFinalizerList = append(newFinalizerList, f)
	}
	is.ObjectMeta.Finalizers = newFinalizerList
}

// IsBeingDeleted returns whether the object is being deleted.
func (is *ImageSigning) IsBeingDeleted() bool {
	return !is.ObjectMeta.DeletionTimestamp.IsZero()
}

// GetCurrentRegistry returns current Registry value in Status.
func (is *ImageSigning) GetCurrentRegistry() string {
	return is.Status.Registry
}

// SetCurrentRegistry sets current Registry value in Status.
func (is *ImageSigning) SetCurrentRegistry(name string) {
	is.Status.Registry = name
}

// GetSpecifiedRegistry returns Registry value in Specification.
func (is *ImageSigning) GetSpecifiedRegistry() string {
	return is.Spec.Registry
}

// IsGenerated returns true if a keypair has been generated
func (is *ImageSigning) IsGenerated() bool {
	log.Info("IsGenerated : " + strconv.FormatBool(is.Status.Generated))
	return is.Status.getGenerated()
}

// IsRegistryModified returns true if Registry value is changed from the currrent status.
func (is *ImageSigning) IsRegistryModified() bool {
	result := is.Status.Registry != is.Spec.Registry
	log.Info("IsRegistryModified : " + strconv.FormatBool(result))
	return result
}

// IsKeyModified returns true if one of values for keypair are changed from the currrent status.
func (is *ImageSigning) IsKeyModified() bool {
	var result bool = true
	if is.Status.getGenerated() {
		if is.Spec.Identity != nil {
			// identity is set.
			id, err := getIdentity(&is.Status.Keypair.SecretKey)
			if err != nil {
				log.Error(err, "getIdentity returns an error")
				// if there is an error, return true to force to recreate key.
				result = true
			} else {
				//return !reflect.DeepEqual(cr.Spec.Identity, &id)
				result = !(*is.Spec.Identity == *id)
			}
		} else if is.Spec.Keypair != nil {
			// keypair is set.
			result = !reflect.DeepEqual(is.Spec.Keypair, is.Status.Keypair)
		}
	}
	log.Info("IsKeyModified : " + strconv.FormatBool(result))
	return result
}

// IsEnabledSyncMachineConfig returns value of SyncMachineConfig.
func (is *ImageSigning) IsEnabledSyncMachineConfig() bool {
	log.Info("IsEnabledSyncMachineConfig : " + strconv.FormatBool(is.Spec.SyncMachineConfig))
	return is.Spec.SyncMachineConfig
}

// IsOwn returns true of secret is owned by this instance.
func (is *ImageSigning) IsOwn(secret *corev1.Secret) bool {
	var result bool = false
	owner := secret.GetOwnerReferences()
	if owner != nil {
		result = owner[0].UID == is.GetUID()
	}
	log.Info("IsOwn : " + strconv.FormatBool(result))
	return result
}

// GeneratKeypair generates or copies keypair in the ImageSiginingSpec to ImageSigningStatus
func (is *ImageSigning) GenerateKeypair() {
	if is.Spec.existsKeypair() {
		// if keypair is supplied, validate the keys and set them.
		// TODO: add validation. make sure that nil check is required.
		// err := errors.New("secretKey and publicKey should be set for importing keypair.")
		log.Info("Importing RSA keypair for image signing.")
		is.Status.setKeypair(is.Spec.Keypair)
		return
	} else if is.Spec.existsIdentity() {
		log.Info("Generating RSA keypair for image signing.")
		is.Status.setIdentity(is.Spec.Identity)
		return
	}
	msg := "Neither Identity nor Keypiar is set."
	log.Info(msg)
	is.Status.deleteGeneratedKeypair(msg)
	return
}
