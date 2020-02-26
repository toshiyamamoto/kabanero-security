package imagesigning

import (
	"context"
	"errors"

	securityv1alpha1 "github.com/kabanero-io/kabanero-security/signing-operator/pkg/apis/security/v1alpha1"
	machineconfigv1 "github.com/openshift/machine-config-operator/pkg/apis/machineconfiguration.openshift.io/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	//	machineconfigv1 "github.com/kabanero-io/kabanero-security/signing-operator/pkg/apis/machineconfiguration.openshift.io/v1"
)

var logisr = logf.Log.WithName("imagesigningreconcile_receiver")

// setNamespece sets specified name to the namespace
func (ris *ReconcileImageSigning) setNamespace(name string) {
	ris.namespace = name
	return
}

// return a secret which stores private key for signing.
func (ris *ReconcileImageSigning) findSecret(name string) (*corev1.Secret, error) {
	sl := corev1.SecretList{}
	err := ris.client.List(context.Background(), &sl, client.InNamespace(ris.namespace))
	if err != nil {
		return nil, err
	}
	for _, _s := range sl.Items {
		if _s.GetName() == name {
			return &_s, nil
		}
	}
	return nil, nil
}

// return ImageSigning CR instance
// If there is only one, return it.
// If there are multiple instances exist, return the one which currently using.
// It can be found by examining Generated field in ImageSigningStatus.
// If there is not the one which has Generated flag, then it's an error condition
// since it cannot determine which one should use.
func (ris *ReconcileImageSigning) findImageSigningInstance() (*securityv1alpha1.ImageSigning, error) {
	isl := securityv1alpha1.ImageSigningList{}
	err := ris.client.List(context.Background(), &isl, client.InNamespace(ris.namespace))
	if err != nil {
		return nil, err
	}
	if items := len(isl.Items); items == 0 {
		// no instance.
		return nil, nil
	} else if items == 1 {
		// only once instance
		return &isl.Items[0], nil
	}
	// if there are multiple, return the one of which status shows generated.
	for _, _is := range isl.Items {
		if _is.IsGenerated() {
			return &_is, nil
		}
	}
	return nil, errors.New("more than one ImageSigning resources found")
}

// if keydata is set, add an entry.
// if keydata or repo is nil or empty string, remove an entry which coresponds with uid from MachineConfig.
func (ris *ReconcileImageSigning) handleMachineConfig(uid types.UID, keydata, registry *string) error {
	// find current MachineConfig
	existMachineConfig := true
	mc, err := ris.findMachineConfig(mcname)
	if err != nil {
		return err
	}
	// if it does not exist, try to get current File object for policy.json from rendered MachineConfig
	if mc == nil {
		mc, err = ris.findRenderedMachineConfig()
		if err != nil {
			return err
		}
		existMachineConfig = false
	}

	pmc, err := newPolicyMachineConfig(uid, mc)
	if err == nil {
		var updated bool
		if keydata != nil && *keydata != "" && registry != nil && *registry != "" {
			// if valid parameters exist, add/update policy
			updated = pmc.modifyPolicy(registry, keydata)
		} else {
			updated = pmc.clearPolicy()
		}

		if updated {
			logisr.Info("MachineConfig is updated")
			err = ris.setMachineConfig(pmc, existMachineConfig)
		}
	}
	return err
}

func (ris *ReconcileImageSigning) findRenderedMachineConfig() (*machineconfigv1.MachineConfig, error) {
	// MachineConfigPool
	mcpl := machineconfigv1.MachineConfigPoolList{}
	err := ris.client.List(context.Background(), &mcpl)
	if err != nil {
		logisr.Error(err, "Failed to access MachineConfigPool.")
		return nil, err
	}
	var mcp *machineconfigv1.MachineConfigPool
	for _, _mcp := range mcpl.Items {
		if _mcp.ObjectMeta.Name == "worker" {
			mcp = &_mcp
			break
		}
	}
	if mcp == nil {
		err := errors.New("no worker machine config pool exists")
		logisr.Error(err, "")
		return nil, err
	}
	name := mcp.Status.Configuration.Name
	logisr.Info("Rendered MachineConfig name" + name)
	// Get rendered MachineConfig
	return ris.findMachineConfig(name)
}

// find specified machine config
func (ris *ReconcileImageSigning) findMachineConfig(name string) (*machineconfigv1.MachineConfig, error) {
	mcl := machineconfigv1.MachineConfigList{}
	err := ris.client.List(context.Background(), &mcl)
	if err != nil {
		logisr.Error(err, "Failed to access MachineCoonfig.")
		return nil, err
	}
	var mc *machineconfigv1.MachineConfig
	for _, _mc := range mcl.Items {
		if _mc.ObjectMeta.Name == name {
			mc = &_mc
			break
		}
	}
	if mc == nil {
		logisr.Info("Machine Config is not found : " + name)
	}
	return mc, nil
}

// save data as 89-policy-json-worker
func (ris *ReconcileImageSigning) setMachineConfig(pmc *PolicyMachineConfig, isUpdate bool) error {
	mc, err := pmc.generateMachineConfig()
	if err != nil {
		return err
	}
	if isUpdate {
		return ris.client.Update(context.Background(), mc)
	} else {
		return ris.client.Create(context.Background(), mc)
	}
}
