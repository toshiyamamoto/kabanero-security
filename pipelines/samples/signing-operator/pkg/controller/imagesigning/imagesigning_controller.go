package imagesigning

import (
	"bytes"
	"context"

	securityv1alpha1 "github.com/kabanero-io/kabanero-security/signing-operator/pkg/apis/security/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

const (
	secretName    = "signature-secret-key"
	secretKeyName = "secret.asc"
	registryName  = "registry"
)

var log = logf.Log.WithName("controller_imagesigning")

/**
* USER ACTION REQUIRED: This is a scaffold file intended for the user to modify with their own Controller
* business logic.  Delete these comments after modifying this file.*
 */

// Add creates a new ImageSigning Controller and adds it to the Manager. The Manager will set fields on the Controller
// and Start it when the Manager is Started.
func Add(mgr manager.Manager) error {
	return add(mgr, newReconciler(mgr))
}

// newReconciler returns a new reconcile.Reconciler
func newReconciler(mgr manager.Manager) reconcile.Reconciler {
	return &ReconcileImageSigning{client: mgr.GetClient(), scheme: mgr.GetScheme(), namespace: ""}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("imagesigning-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Watch for changes to primary resource ImageSigning
	err = c.Watch(&source.Kind{Type: &securityv1alpha1.ImageSigning{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	// Create secret predicate to reduce unnecessary event handling.
	sPred := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			return false
		},
		GenericFunc: func(e event.GenericEvent) bool {
			return false
		},
		DeleteFunc: func(e event.DeleteEvent) bool {
			if e.Meta.GetName() == secretName {
				return true
			}
			return false
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			return false
		},
	}

	// Watch for changes to the secrt which is not owned by ImageSigning.
	// If the secret which is not owned by ImageSigning CR, a new secret is
	// generated.
	err = c.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForObject{}, sPred)
	if err != nil {
		return err
	}

	return nil
}

// blank assignment to verify that ReconcileImageSigning implements reconcile.Reconciler
var _ reconcile.Reconciler = &ReconcileImageSigning{}

// ReconcileImageSigning reconciles a ImageSigning object
type ReconcileImageSigning struct {
	// This client, initialized using mgr.Client() above, is a split client
	// that reads objects from the cache and writes to the apiserver
	client    client.Client
	scheme    *runtime.Scheme
	namespace string
}

// Reconcile reads that state of the cluster for a ImageSigning object and makes changes based on the state read
// and what is in the ImageSigning.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (ris *ReconcileImageSigning) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling ImageSigning")
	ris.setNamespace(request.Namespace)

	// get custom resource
	is, err := ris.findImageSigningInstance()
	if err != nil {
		// Error reading the object - requeue the request.
		reqLogger.Error(err, "Failed to get ImageSigning instance.")
		return reconcile.Result{}, err
	}

	// Find existing imagesigning secret
	secret, err := ris.findSecret(secretName)
	if err != nil {
		reqLogger.Error(err, "Failed to get ImageSigning secret.")
		return reconcile.Result{}, err
	}

	if is != nil {
		// check deletion time.
		if is.IsBeingDeleted() {
			// clear machine config, ignore an error.
			if is.IsEnabledSyncMachineConfig() {
				err = ris.handleMachineConfig(is.GetUID(), nil, nil)
				reqLogger.Error(err, "Failed to update MachineConfig. Ignoring.")
			}
			is.ClearFinalizer()
			err = ris.client.Update(context.TODO(), is)
			if err != nil {
				reqLogger.Error(err, "Failed to update ImageSigning CRD. Ignoring.")
			}
			return reconcile.Result{}, nil
		}
		// set finalizer for deletion.
		if is.SetFinalizer() {
			err = ris.client.Update(context.TODO(), is)
			if err != nil {
				reqLogger.Error(err, "Failed to update ImageSigning CRD. Ignoring.")
			}
		}

		if secret != nil && !is.IsOwn(secret) {
			// secret is not owned by me, do nothing.
			reqLogger.Info("found ImageSigning secret. Do nothing.")
			return reconcile.Result{}, nil
		}
	}
	if is == nil {
		reqLogger.Info("No ImageSigning CR. Do nothing.")
		return reconcile.Result{}, nil
	}

	regModified := is.IsRegistryModified()
	keyModified := is.IsKeyModified()

	if secret == nil || regModified || keyModified || !is.IsGenerated() {
		if keyModified {
			is.GenerateKeypair()
		}
		// update registry name
		specifiedRegistry := is.GetSpecifiedRegistry()
		if regModified {
			is.SetCurrentRegistry(specifiedRegistry)
		}
		// update status since some status value has been changed.
		err = ris.client.Status().Update(context.TODO(), is)
		if err != nil {
			reqLogger.Error(err, "Failed to update ImageSigning status.")
			return reconcile.Result{}, err
		}

		// create secret
		//TODO implement deletin a secret when generated keys no longer exists.
		privateKey := is.Status.GetPrivateKey()
		if secret == nil {
			if privateKey != "" {
				// key is generated.
				reqLogger.Info("Create a new secret")
				secret := createSecret(is.GetNamespace(), &specifiedRegistry, &privateKey)
				controllerutil.SetControllerReference(is, secret, ris.scheme)
				err = ris.client.Create(context.TODO(), secret)
			}
		} else {
			if privateKey != "" {
				if updateSecret(secret, &specifiedRegistry, &privateKey) {
					reqLogger.Info("Update existing secret")
					err = ris.client.Update(context.TODO(), secret)
				}
			} else {
				// delete existing secret.
				reqLogger.Info("Delete existing secret")
				err = ris.client.Delete(context.TODO(), secret)
			}
		}
		if err != nil {
			reqLogger.Error(err, "Failed to handle ImageSigning secret.")
			return reconcile.Result{}, err
		}

		// handle machine config
		if is.IsEnabledSyncMachineConfig() {
			publicKey := is.Status.GetPublicKey()
			err = ris.handleMachineConfig(is.GetUID(), &publicKey, &specifiedRegistry)
		}
	}
	return reconcile.Result{}, err
}

// create a secret named signature-secret-key which contains two elements.
// secret.asc is a secret key which will be used for signing the images.
// registry is a registry name for signature.
func createSecret(namespace string, registry *string, armoredPrivateKey *string) *corev1.Secret {
	m := map[string][]byte{}
	m[secretKeyName] = []byte(*armoredPrivateKey)
	m[registryName] = []byte(*registry)
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Data: m,
	}
}

// create a secret named signature-secret-key which contains two elements.
// secret.asc is a secret key which will be used for signing the images.
// registry is a registry name for signature.
func updateSecret(secret *corev1.Secret, registry *string, armoredPrivateKey *string) bool {
	var updated bool
	registryData := []byte(*registry)
	if bytes.Compare(secret.Data[registryName], registryData) != 0 {
		secret.Data[registryName] = registryData
		updated = true
	}
	keyData := []byte(*armoredPrivateKey)
	if bytes.Compare(secret.Data[secretKeyName], keyData) != 0 {
		secret.Data[secretKeyName] = keyData
		updated = true
	}
	return updated
}
