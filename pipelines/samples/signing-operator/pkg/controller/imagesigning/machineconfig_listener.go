package imagesigning

import (
	"context"
	"errors"

	igntypes "github.com/coreos/ignition/config/v2_2/types"
	"github.com/go-logr/logr"
	machineconfigv1 "github.com/openshift/machine-config-operator/pkg/apis/machineconfiguration.openshift.io/v1"
	"k8s.io/apimachinery/pkg/labels"
)

var (
	policyfilename = "/etc/containers/policy.json"
	mcname         = "89-policy-json-worker"
	mode           = 420
)

// if keydata is set, add an entry.
// if keydata is null, remove an entry which is specified by repo from machine config.
func handleMachineConfig(r *ReconcileImageSigning, keydata *string, repo *string, reqLogger logr.Logger) error {
	// find current MachineConfig, if it does not exist, try to get one from rendered MachineConfig
	mc, err := findMC(r, &mcname, reqLogger)
	if err != nil {
		return err
	}
	if mc == nil {
		// getCurrent File Config of policy.json.
		mc, err = findRMC(r, reqLogger)
		if err != nil {
			return err
		}
	}
	orgfc := getFileConfig(mc, policyfilename)
	reqLogger.Info("Toshi: orgfc : " + orgfc.Contents.Source)

	// TODO: if FileConfig is nil, create a default one.

	policy, err := getPolicy(&orgfc.Contents.Source, reqLogger)
	if err != nil {
		reqLogger.Error(err, "")
		return err
	}

	// repo := "image-registry.openshift-image-registry.svc:5000/kabanero-signed"

	////	keydata := "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxsBNBF5FifMBCADfyraEaLUerLGE6p5gVRvZP26lC6MjzJRtvjEU6iJ02VOHA06R\n1AvImDKFtj3acouLMwwIgoW2wEtfnrTdGbLg61Fxfu6fDNW8fZl3aK3K2/HISoTf\n4zmMlSyP6MgxtbJbLw/yaWx39XMre9Y6bxG5BCkfDgy+DMoEHfjmAIFv+cPzxlB9\niB3WLwtUMn2fMlYIzqwcJuqqIBzka1pCv9Yq+z6UCKNbYcs0z/eObn0Rz3twBa/I\nMbUmTR8lzgHM6NyskG25HJtINwviuxZWp+K+YgvV86+GG6r45pOAUI1rCR9DsqgE\n719SVb45+UT3Wzt+ThLN2xzIRFlZ5KLhU7txABEBAAHNI0ltYWdlU2lnbmluZyA8\nc2VjdXJpdHlAZXhhbXBsZS5jb20+wsBiBBMBCAAWBQJeRYnzCRC3ZDy0xb3Q8AIb\nAwIZAQAApagIAIblomoAa6wUfAmNBqhfAiktXBrEqz4hDCcOVZPni60UyF8wXPWB\niEeQcPUxznhlh8lF0skn/raWu8RYI8QSfHJ1wAqZPqB1cCbK5A6kI+uXLMS6OkIk\nGWfTTAgtFW2W36hRSvjBW1jQox1NQOdXh6n5N0IliQu4Zq1x5Tfg/jRAMzRhUjJf\nLkXhYSIIEkFX42iHKLK4ZY+QnUx9UwwmSoe2AT7ft6Ol16SDt+JlQiEvEPrA1eCt\nNlHKim+GTn84xb4KPcbWM4dr3/cKLFGzBEGICdNrLRKtHfS4A0YH4YaQqrgHYyBQ\nzT6FYfn4YsNhAuJ93JP2OESlR8+ggQmZ6HE=\n=XMXB\n-----END PGP PUBLIC KEY BLOCK-----"
	//keydata := "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxsANBF5FifMBCADfyraEaLUerLGE6p5gVRvZP26lC6MjzJRtvjEU6iJ02VOHA06R\n1AvImDKFtj3acouLMwwIgoW2wEtfnrTdGbLg61Fxfu6fDNW8fZl3aK3K2/HISoTf\n4zmMlSyP6MgxtbJbLw/yaWx39XMre9Y6bxG5BCkfDgy+DMoEHfjmAIFv+cPzxlB9\niB3WLwtUMn2fMlYIzqwcJuqqIBzka1pCv9Yq+z6UCKNbYcs0z/eObn0Rz3twBa/I\nMbUmTR8lzgHM6NyskG25HJtINwviuxZWp+K+YgvV86+GG6r45pOAUI1rCR9DsqgE\n719SVb45+UT3Wzt+ThLN2xzIRFlZ5KLhU7txABEBAAHNI0ltYWdlU2lnbmluZyA8\nc2VjdXJpdHlAZXhhbXBsZS5jb20+wsBiBBMBCAAWBQJeRYnzCRC3ZDy0xb3Q8AIb\nAwIZAQAApagIAIblomoAa6wUfAmNBqhfAiktXBrEqz4hDCcOVZPni60UyF8wXPWB\niEeQcPUxznhlh8lF0skn/raWu8RYI8QSfHJ1wAqZPqB1cCbK5A6kI+uXLMS6OkIk\nGWfTTAgtFW2W36hRSvjBW1jQox1NQOdXh6n5N0IliQu4Zq1x5Tfg/jRAMzRhUjJf\nLkXhYSIIEkFX42iHKLK4ZY+QnUx9UwwmSoe2AT7ft6Ol16SDt+JlQiEvEPrA1eCt\nNlHKim+GTn84xb4KPcbWM4dr3/cKLFGzBEGICdNrLRKtHfS4A0YH4YaQqrgHYyBQ\nzT6FYfn4YsNhAuJ93JP2OESlR8+ggQmZ6HE=\n=XMXB\n-----END PGP PUBLIC KEY BLOCK-----"
	updated, err := updatePolicy(policy, repo, keydata)

	if updated {
		reqLogger.Info("Toshi: after update : UPDATED")
		err = setCurrentPolicy(r, mc, &orgfc, policy, reqLogger)
	} else {
		reqLogger.Info("Toshi: after update : NO UPDATE")
	}

	return err
}

// save data as 89-policy-json-worker.
func setCurrentPolicy(r *ReconcileImageSigning, rmc *machineconfigv1.MachineConfig, file *igntypes.File, policy *Policy, reqLogger logr.Logger) error {
	data, err := convertEncodedData(policy, reqLogger)
	if err != nil {
		return err
	}
	reqLogger.Info("Toshi: updated data : " + *data)

	currentmc, err := findMC(r, &mcname, reqLogger)
	if err != nil {
		return err
	}
	file.Contents.Source = *data
	if currentmc == nil {
		var mc machineconfigv1.MachineConfig
		// copy as much data from the rendered machine config
		mc.TypeMeta.APIVersion = rmc.TypeMeta.APIVersion
		mc.TypeMeta.Kind = rmc.TypeMeta.Kind
		mc.ObjectMeta.Name = mcname
		mc.Labels = labels.Set{"machineconfiguration.openshift.io/role": "worker"}
		mc.Spec = machineconfigv1.MachineConfigSpec{}
		mc.Spec.Config.Ignition = rmc.Spec.Config.Ignition
		mc.Spec.Config.Storage = igntypes.Storage{Files: []igntypes.File{*file}}
		err = r.client.Create(context.Background(), &mc)
	} else {
		currentmc.Spec.Config.Storage = igntypes.Storage{Files: []igntypes.File{*file}}
		err = r.client.Update(context.Background(), currentmc)
	}

	return err
}

func findRMC(r *ReconcileImageSigning, reqLogger logr.Logger) (*machineconfigv1.MachineConfig, error) {
	// MachineConfigPool
	mcpl := machineconfigv1.MachineConfigPoolList{}
	err := r.client.List(context.Background(), &mcpl)
	if err != nil {
		reqLogger.Error(err, "Failed to access MachineConfigPool.")
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
		reqLogger.Error(err, "")
		return nil, err
	}
	name := mcp.Status.Configuration.Name
	reqLogger.Info("Toshi: rendered name" + name)

	// Get rendered MachineConfig
	return findMC(r, &name, reqLogger)
}

// find specified machine config
func findMC(r *ReconcileImageSigning, name *string, reqLogger logr.Logger) (*machineconfigv1.MachineConfig, error) {
	mcl := machineconfigv1.MachineConfigList{}
	err := r.client.List(context.Background(), &mcl)
	if err != nil {
		reqLogger.Error(err, "Failed to access MachineCoonfig.")
		return nil, err
	}
	var mc *machineconfigv1.MachineConfig
	for _, _mc := range mcl.Items {
		if _mc.ObjectMeta.Name == *name {
			mc = &_mc
			break
		}
	}
	if mc == nil {
		reqLogger.Info("Machine Config is not found : " + *name)
	}
	return mc, nil
}

// get last FileConfig object which matches the specified by path from a machine config
func getFileConfig(mc *machineconfigv1.MachineConfig, path string) igntypes.File {
	flist := mc.Spec.Config.Storage.Files
	var file igntypes.File
	// find the last match.
	for _, _file := range flist {
		if _file.Path == path {
			file = _file
		}
	}
	return file
}
