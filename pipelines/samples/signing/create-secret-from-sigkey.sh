#!/bin/bash
#set namespace
namespace=kabanero
signby=security@example.com
signedimagerepo=image-registry.openshift-image-registry.svc:5000/$namespace-signed

cat <<EOF | oc -n ${namespace} apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: signature-secret-key
data:
  secret.asc: $(gpg --export-secret-keys ${signby} | base64 -w 0)
  registry: $(echo ${signedimagerepo} | base64 -w 0)
EOF
