package imagesigning

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"reflect"
	"strings"

	"github.com/go-logr/logr"
)

const (
	typevalue    = "signedBy"
	keytypevalue = "GPGKeys"
)

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

// RepoMap map repo name to policycontent for each repo
type RepoMap map[string][]PolicyData

// Transports struct for content under "transports"
type Transports map[string]RepoMap

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
func createDefaultPolicy() *Policy {
	var policy Policy

	return &policy
}

// GetPolicy parse given data into PolicyContent struct
// the data is following format
// "data:,<url encoded json string>"
func getPolicy(data *string, reqLogger logr.Logger) (*Policy, error) {
	// decode url encoding.
	decoded, err := url.QueryUnescape(*removeHeader(data))
	if err != nil {
		reqLogger.Error(err, "failed to decode url encoding")
		return nil, err
	}
	reqLogger.Info("Toshi: original : " + decoded)
	var policy Policy

	if err := json.Unmarshal([]byte(decoded), &policy); err != nil {
		return nil, err
	}
	return &policy, nil
}

func convertEncodedData(policy *Policy, reqLogger logr.Logger) (*string, error) {
	text, err := json.Marshal(policy)
	if err != nil {
		return nil, err
	}
	reqLogger.Info("Toshi: modified : " + string(text))
	output := "data:," + url.QueryEscape(string(text))
	return &output, nil
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

// if oldRepo is not nil, delete the entry.
// if repo is not nil, create/update an entry.
func addPolicy(policy *Policy, repo, keydata *string) (bool, error) {
	var updated bool
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
	if updated || !equalsPolicyData(repos[*repo], &pd) {
		repos[*repo] = make([]PolicyData, 1)
		repos[*repo][0] = pd
		updated = true
	}
	return updated, nil
}

// if oldRepo is not nil, delete the entry.
// if repo is not nil, create/update an entry.
func deletePolicy(policy *Policy, repo *string) bool {
	var updated bool

	// removing the entry.
	if policy.Transports != nil {
		repos := policy.Transports["docker"]
		if repos != nil {
			if repos[*repo] != nil {
				// entry exists, delete it.
				delete(repos, *repo)
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

// check the complete match in list of PolicyData.
func equalsPolicyData(pds []PolicyData, pd *PolicyData) bool {
	if len(pds) == 1 {
		return reflect.DeepEqual(&pds[0], pd)
	}
	return false
}
