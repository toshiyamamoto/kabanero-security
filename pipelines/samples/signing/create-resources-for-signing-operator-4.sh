#!/bin/bash
# set namespace. the default is kabanero
NAMESPACE=kabanero

# set a signature storage location.
# this is used in order to store generated signatures for the images.
# thus write access by the pod user (non root) needs to be granted.
# if PersistentVolume is used, this value is not required.
HOST_SIGNATURE_STORAGE_DIR="/var/tmp"
#HOST_SIGNATURE_STORAGE_DIR="/mnt/signtask"

SIGNATURE_STORAGE_ROOT="/mnt/signtask"
SIGNATURE_STORAGE_DIR=$SIGNATURE_STORAGE_ROOT/sigstore
SOURCE_TRANSPORT="docker://"
SIGNED_TRANSPORT="docker://"

# get internal docker registry. this might not work for OpenShift v4.
REGISTRY_HOST=$(oc get image.config.openshift.io/cluster -o yaml|grep internalRegistryHostname|awk '{print $2}')
echo "Registry host : ${REGISTRY_HOST}"

if [ $REGISTRY_HOST ]; then
echo "Create default.yaml file which will be mounted in /etc/containers/registries.d"
cat <<EOF | oc -n $NAMESPACE apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: registry-d-default
data:
  default.yaml: |
    # This is a default registries.d configuration file.
    # This file may be modified in order to configure the location of look aside signature store.
    # Please refer to /etc/containers/registries.d/default.yaml file for more information.
    default-docker:
    # no default value in order to let skopeo push the signature to the internal docker registry.
    docker:
      docker.io:
        # the directory below may be shared disk in order to accessing the signature from any nodes.
        sigstore: file://$SIGNATURE_STORAGE_DIR
        sigstore-staging: file://$SIGNATURE_STORAGE_DIR
EOF

echo "Applying sign-task"
cat <<EOF | oc -n $NAMESPACE apply -f -
apiVersion: tekton.dev/v1alpha1
kind: Task
metadata:
  name: sign-task
spec:
  inputs:
    resources:
      - name: source-image
        type: image
      - name: signed-image
        type: image
  steps:
    - name: sign-image
      securityContext: {}
      image: $REGISTRY_HOST/kabanero/signer
      command: ['/bin/bash']
      args: ['-c', 'REPO=\`cat /etc/gpg/registry\`; if [[ \$(inputs.resources.signed-image.url) != \$REPO/* ]];then echo "The specified signed image repository does not match the name of the repository in sign-secret-key secret resource. The repository name should start with \$REPO, Specified signed image name is \$(inputs.resources.signed-image.url)"; exit 1; fi; gpg --import /etc/gpg/secret.asc ; SIGNBY=\`gpg --list-keys|sed -n -e "/.*<.*>.*/p"|sed -e "s/^.*<\(.*\)>.*$/\1/"\` ; skopeo --debug copy --dest-tls-verify=false --src-tls-verify=false --remove-signatures --sign-by \$SIGNBY $SOURCE_TRANSPORT\$(inputs.resources.source-image.url) $SIGNED_TRANSPORT\$(inputs.resources.signed-image.url)']
      volumeMounts:
        - name: sign-secret-key
          mountPath: /etc/gpg
        - name: registries-d-dir
          mountPath: /etc/containers/registries.d
        - name: signature-storage
          mountPath: $SIGNATURE_STORAGE_ROOT
  volumes:
    - name: sign-secret-key
      secret:
        secretName: signature-secret-key
    - name: registries-d-dir
      configMap:
        name: registry-d-default  
    - name: signature-storage
##      persistentVolumeClaim:
##        claimName: signature-storage
      hostPath:
        path: $HOST_SIGNATURE_STORAGE_DIR
EOF

echo "Applying sign-pipeline"
cat <<EOF | oc -n $NAMESPACE apply -f -
apiVersion: tekton.dev/v1alpha1
kind: Pipeline
metadata:
  name: sign-pipeline
spec:
  resources:
    - name: source-image
      type: image
    - name: signed-image
      type: image
  tasks:
    - name: kabanero-sign
      taskRef:
        name: sign-task
      resources:
        inputs:
        - name: source-image
          resource: source-image
        - name: signed-image
          resource: signed-image
EOF
fi
