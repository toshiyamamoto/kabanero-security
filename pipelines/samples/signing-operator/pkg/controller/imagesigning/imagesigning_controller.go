package imagesigning

import (
	"context"
	"reflect"
	"strconv"

	securityv1alpha1 "github.com/kabanero-io/kabanero-security/signing-operator/pkg/apis/security/v1alpha1"
	corev1 "k8s.io/api/core/v1"
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
	return &ReconcileImageSigning{client: mgr.GetClient(), scheme: mgr.GetScheme()}
}

// add adds a new Controller to mgr with r as the reconcile.Reconciler
func add(mgr manager.Manager, r reconcile.Reconciler) error {
	// Create a new controller
	c, err := controller.New("imagesigning-controller", mgr, controller.Options{Reconciler: r})
	if err != nil {
		return err
	}

	// Create crd predicate to reduce unnecessary event handling.
	crdPred := predicate.Funcs{
		CreateFunc: func(e event.CreateEvent) bool {
			log.Info("CRD CreateEvent")
			return true
		},
		GenericFunc: func(e event.GenericEvent) bool {
			log.Info("CRD GenericEvent")
			return false
		},
		UpdateFunc: func(e event.UpdateEvent) bool {
			result := !reflect.DeepEqual(e.ObjectOld, e.ObjectNew)
			if result {
				log.Info("CRD UpdateEvent : true")
			} else {
				log.Info("CRD UpdateEvent : false")
			}
			return !reflect.DeepEqual(e.ObjectOld, e.ObjectNew)
		},
	}
	// Watch for changes to primary resource ImageSigning
	err = c.Watch(&source.Kind{Type: &securityv1alpha1.ImageSigning{}}, &handler.EnqueueRequestForObject{}, crdPred)
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
	client client.Client
	scheme *runtime.Scheme
}

// Reconcile reads that state of the cluster for a ImageSigning object and makes changes based on the state read
// and what is in the ImageSigning.Spec
// Note:
// The Controller will requeue the Request to be processed again if the returned error is non-nil or
// Result.Requeue is true, otherwise upon completion it will remove the work from the queue.
func (r *ReconcileImageSigning) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	reqLogger := log.WithValues("Request.Namespace", request.Namespace, "Request.Name", request.Name)
	reqLogger.Info("Reconciling ImageSigning")
	var updated bool

	// get custom resource
	cr, err := findCR(r, request.Namespace)
	if err != nil {
		// Error reading the object - requeue the request.
		reqLogger.Error(err, "Failed to get ImageSigning resource.")
		return reconcile.Result{}, err
	}

	// Find existing imagesigning secret
	secret, err := findSecret(r, request.Namespace)
	if err != nil {
		reqLogger.Error(err, "Failed to get ImageSigning secret.")
		return reconcile.Result{}, err
	}
	if secret != nil {
		if cr != nil && isOwned(secret, cr.GetUID()) {
			currentRepo := &cr.Status.Registry
			// TODO: need to check whether it's owned by me.
			if cr == nil {
				reqLogger.Info("ImageSigning CR is not found.")
				// clean up machine config.
				reqLogger.Info("Registry name : " + *currentRepo)
				err = deleteMachineConfig(r, currentRepo, reqLogger)
				return reconcile.Result{}, err
			}
		} else {
			// secret is not owned by me, do nothing.
			reqLogger.Info("found ImageSigning secret. Do nothing.")
			return reconcile.Result{}, nil
		}
	} else {
		updated = true
	}
	if cr == nil {
		reqLogger.Info("No ImageSigning CR. Do nothing.")
		return reconcile.Result{}, nil
	}
	// TODO add crd has been updated.
	// check whether CRD has been updated
	repoModified := cr.Status.Registry != cr.Spec.Registry
	keyModified := isKeyModified(cr, reqLogger)
	updated = updated || repoModified || keyModified || !cr.Status.Generated
	reqLogger.Info("!!!TOSHI : repo :" + strconv.FormatBool(repoModified) + ", keyModified : " + strconv.FormatBool(keyModified) + ", generated : " + strconv.FormatBool(cr.Status.Generated))
	if updated {
		var currentRepo *string
		if keyModified {
			// create Entity from the public key.
			err = generateKeyPair(&cr.Spec, &cr.Status, reqLogger)
			if err != nil {
				return reconcile.Result{}, err
			}
		}
		// update registry name.
		if repoModified {
			instance := cr.Status.Registry
			currentRepo = &instance
			cr.Status.Registry = cr.Spec.Registry
		}
		// update status since a new keypair has generated.
		err = r.client.Status().Update(context.TODO(), cr)
		if err != nil {
			reqLogger.Error(err, "Failed to update ImageSigning status.")
			return reconcile.Result{}, err
		}

		// create secret
		if secret == nil {
			secret, err := createSecret(&cr.ObjectMeta.Namespace, &cr.Spec.Registry, &cr.Status.Keypair.SecretKey)
			if err != nil {
				reqLogger.Error(err, "Failed to create a new ImageSigning secret.")
				return reconcile.Result{}, err
			}
			reqLogger.Info("Create a new secret")
			controllerutil.SetControllerReference(cr, secret, r.scheme)
			err = r.client.Create(context.TODO(), secret)
		} else {
			if updateSecret(secret, &cr.Status.Registry, &cr.Status.Keypair.SecretKey, reqLogger) {
				reqLogger.Info("Update existing secret")
				err = r.client.Update(context.TODO(), secret)
			}
		}
		if err != nil {
			reqLogger.Error(err, "Failed to create or update a new ImageSigning secret.")
			return reconcile.Result{}, err
		}

		reqLogger.Info("Toshi : repo : " + cr.Spec.Registry + ", keydata : " + cr.Status.Keypair.SecretKey)
		// handle machine config
		err = handleMachineConfig(r, &cr.Status.Keypair.SecretKey, &cr.Spec.Registry, currentRepo, reqLogger) // TODO
	}
	return reconcile.Result{}, err
}
