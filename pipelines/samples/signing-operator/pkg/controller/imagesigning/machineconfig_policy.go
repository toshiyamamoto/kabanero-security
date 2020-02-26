package imagesigning

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	igntypes "github.com/coreos/ignition/config/v2_2/types"
	machineconfigv1 "github.com/openshift/machine-config-operator/pkg/apis/machineconfiguration.openshift.io/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	registrymaptag = "kabanero.security.imagesigning.registries"
	typevalue      = "signedBy"
	keytypevalue   = "GPGKeys"
	policyfilename = "/etc/containers/policy.json"
	mcname         = "89-policy-json-worker"
	nopolicy       = "insecureAcceptAnything"
	rolelabel      = "machineconfiguration.openshift.io/role"
)

// map of UID and Repository name
type RegistryMap map[string]string

// Custom Machine Config
type PolicyMachineConfig struct {
	UID           types.UID
	MachineConfig *machineconfigv1.MachineConfig
	Policy        *Policy
	Registries    RegistryMap
}

// Policy struct for policy.json file
type Policy struct {
	Default    []PolicyData `json:"default"`
	Transports Transports   `json:"transports"`
}

// Repo struct used under each repo
type PolicyData struct {
	Type           string          `json:"type"`
	KeyType        string          `json:"keyType,omitempty"`
	KeyPath        string          `json:"keyPath,omitempty"`
	KeyData        string          `json:"keyData,omitempty"`
	SignedIdentity json.RawMessage `json:"signedIdentity,omitempty"`
}

// RepoMap map repo name to policycontent for each repository
type RepoMap map[string][]PolicyData

// Transports struct for content under "transports"
type Transports map[string]RepoMap

var logpmc = logf.Log.WithName("machineconfig_policy")

// newPolicyMachineConfig  creates a new object from existing MachineConfig of policy.json
func newPolicyMachineConfig(uid types.UID, mc *machineconfigv1.MachineConfig) (*PolicyMachineConfig, error) {
	var (
		policy     *Policy
		registries RegistryMap
		err        error
	)
	if mc != nil {
		// get Policy and RegistryMap from current MachineConfig
		file := getPolicyFileConfig(mc)
		if file != nil {
			policy, err = newPolicy(&file.Contents.Source)
		}
		if err == nil {
			registries, err = getRegistryMap(mc)
		}
		if err != nil {
			return nil, err
		}
	}
	if policy == nil {
		policy = newDefaultPolicy()
	}
	if registries == nil {
		registries = make(RegistryMap)
		logpmc.Info("new registry map is created.")
	}

	return &PolicyMachineConfig{UID: uid, MachineConfig: mc, Policy: policy, Registries: registries}, nil
}

// isNew returrns whether this object is newly created
func (pmc *PolicyMachineConfig) isNew() bool {
	_, value := pmc.MachineConfig.Labels[rolelabel]
	logpmc.Info("isNew : " + strconv.FormatBool(!value))
	return !value
}

// if oldRepo is not nil, delete the entry.
// if repo is not nil, create/update an entry.
func (pmc *PolicyMachineConfig) modifyPolicy(registry, keydata *string) bool {
	var updated bool
	if pmc.Registries == nil {
		logpmc.Info("TOSHI registry map is null.... ")
		return false
	}
	currentRegistry := pmc.Registries[string(pmc.UID)]
	logpmc.Info("Configured Registry : " + currentRegistry)

	if *registry != currentRegistry {
		if currentRegistry != "" {
			// delete the old one.
			pmc.clearPolicy()
		}
		pmc.Registries[string(pmc.UID)] = *registry
		updated = true
	}

	policy := pmc.Policy
	// adding the entry.
	// find whether a repo already exists.
	if policy.Transports == nil {
		// if there is no transports, create it.
		policy.Transports = map[string]RepoMap{}
		updated = true
	}
	repos := policy.Transports["docker"]
	if repos == nil {
		// if there is no docker transport, create it.
		policy.Transports["docker"] = RepoMap{}
		repos = policy.Transports["docker"]
		updated = true
	}
	// create/update the contents
	var pd PolicyData
	pd.Type = typevalue
	pd.KeyType = keytypevalue
	pd.KeyPath = ""
	pd.KeyData = base64.StdEncoding.EncodeToString([]byte(*keydata))
	pd.SignedIdentity = nil
	if updated || !equalsPolicyData(repos[*registry], &pd) {
		repos[*registry] = make([]PolicyData, 1)
		repos[*registry][0] = pd
		updated = true
	}
	return updated
}

// if oldRepo is not nil, delete the entry.
// if repo is not nil, create/update an entry.
func (pmc *PolicyMachineConfig) clearPolicy() bool {
	var updated bool
	currentRegistry := pmc.Registries[string(pmc.UID)]
	logpmc.Info("Delete Registry : " + currentRegistry)
	if currentRegistry != "" {
		delete(pmc.Registries, string(pmc.UID))
		updated = true
	}
	policy := pmc.Policy
	// removing the entry.
	if policy.Transports != nil {
		repos := policy.Transports["docker"]
		if repos != nil {
			if repos[currentRegistry] != nil {
				// entry exists, delete it.
				delete(repos, currentRegistry)
				// if there is no entry, delete transport as well.
				if len(repos) == 0 {
					delete(policy.Transports, "docker")
				}
				updated = true
			}
		}
	}
	return updated
}

// save data as 89-policy-json-worker.
func (pmc *PolicyMachineConfig) generateMachineConfig() (*machineconfigv1.MachineConfig, error) {
	data, err := pmc.Policy.convertEncodedData()
	if err != nil {
		return nil, err
	}
	logpmc.Info("Toshi: updated policy : " + *data)
	file := getPolicyFileConfig(pmc.MachineConfig)
	if file == nil {
		file = createNewFile()
	}
	file.Contents.Source = *data
	if pmc.isNew() {
		var mc machineconfigv1.MachineConfig
		// copy as much data from the rendered machine config
		mc.TypeMeta.APIVersion = pmc.MachineConfig.TypeMeta.APIVersion
		mc.TypeMeta.Kind = pmc.MachineConfig.TypeMeta.Kind
		mc.ObjectMeta.Name = mcname
		mc.Labels = labels.Set{rolelabel: "worker"}
		mc.Spec = machineconfigv1.MachineConfigSpec{}
		mc.Spec.Config.Ignition = pmc.MachineConfig.Spec.Config.Ignition
		mc.Spec.Config.Storage = igntypes.Storage{Files: []igntypes.File{*file}}
		setRegistryMap(&mc, &pmc.Registries)
		return &mc, nil
	}
	pmc.MachineConfig.Spec.Config.Storage = igntypes.Storage{Files: []igntypes.File{*file}}
	setRegistryMap(pmc.MachineConfig, &pmc.Registries)
	return pmc.MachineConfig, nil
}

func (policy *Policy) convertEncodedData() (*string, error) {
	text, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	output := "data:," + url.QueryEscape(string(text))
	return &output, nil
}

// create a policy object which contains default value.
//{
//    "default": [
//        {
//            "type": "insecureAcceptAnything"
//        }
//    ],
//    "transports":
//        {
//            "docker-daemon":
//                {
//                    "": [{"type":"insecureAcceptAnything"}]
//                }
//        }
//}
func newDefaultPolicy() *Policy {
	policy := Policy{}
	policy.Default = make([]PolicyData, 1)
	pd := PolicyData{}
	pd.Type = nopolicy
	policy.Default[0] = pd
	policy.Transports = make(Transports)
	repos := make(RepoMap)
	repos[""] = make([]PolicyData, 1)
	repos[""][0] = pd
	policy.Transports["docker-daemon"] = repos
	return &policy
}

// GetPolicy parse given data into PolicyContent struct
// the data is following format
// "data:,<url encoded json string>"
func newPolicy(data *string) (*Policy, error) {
	// decode url encoding.
	decoded, err := url.QueryUnescape(*removeHeader(data))
	if err != nil {
		logpmc.Error(err, "failed to decode url encoding")
		return nil, err
	}
	var policy Policy
	if err := json.Unmarshal([]byte(decoded), &policy); err != nil {
		logpmc.Error(err, "failed to decode json")
		return nil, err
	}
	return &policy, nil
}

// remove tag "data:,"
func removeHeader(data *string) *string {
	// Get substring after a string.
	pos := strings.Index(*data, ",")
	if pos == -1 {
		return data
	}
	result := (*data)[pos+1 : len(*data)]
	return &result
}

// check the complete match in list of PolicyData.
func equalsPolicyData(pds []PolicyData, pd *PolicyData) bool {
	if len(pds) == 1 {
		return reflect.DeepEqual(&pds[0], pd)
	}
	return false
}

// returns policy,json file object
func getPolicyFileConfig(mc *machineconfigv1.MachineConfig) *igntypes.File {
	return getFileConfig(mc, policyfilename)
}

// get last FileConfig object which matches the specified by path from a machine config
func getFileConfig(mc *machineconfigv1.MachineConfig, path string) *igntypes.File {
	flist := mc.Spec.Config.Storage.Files
	var file igntypes.File
	// find the last match.
	for _, _file := range flist {
		if _file.Path == path {
			file = _file
		}
	}
	return &file
}

// get last RegistryMap annotation
func getRegistryMap(mc *machineconfigv1.MachineConfig) (RegistryMap, error) {
	annotations := mc.GetAnnotations()
	data := annotations[registrymaptag]
	if data != "" {
		// data is json format.
		instance := make(RegistryMap)
		err := json.Unmarshal([]byte(data), &instance)
		if err != nil {
			return nil, err
		}
		return instance, nil
	}
	return nil, nil
}

// get last RegistryMap annotation
func setRegistryMap(mc *machineconfigv1.MachineConfig, registries *RegistryMap) error {
	regdata, err := json.Marshal(registries)
	if err != nil {
		return err
	}
	logpmc.Info("Toshi: updated registrymap : " + string(regdata))
	data := make(map[string]string)
	data[registrymaptag] = string(regdata)
	mc.SetAnnotations(data)
	return nil
}

func createNewFile() *igntypes.File {
	filemode := 420
	instance := igntypes.File{}
	instance.Filesystem = "root"
	instance.Path = policyfilename
	instance.Mode = &filemode
	return &instance

}
