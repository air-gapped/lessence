#!/usr/bin/env bash
# Captures a real Kubernetes API-server audit log from a throwaway kind
# cluster: about three minutes of deploys, rollouts, failures, denied calls,
# exec, a node drain and deletes. The cluster is created and deleted here and
# the caller's kubeconfig is never touched.
#
#   scripts/capture-audit-log.sh <output.log>
#
# Needs kind, docker and kubectl. The output is raw material for a corpus:
# it goes to examples/originals/ and is distilled and anonymised from there
# (docs/distill.md), never committed.
set -euo pipefail

out="${1:?usage: scripts/capture-audit-log.sh <output.log>}"
name="lessence-audit-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
work=$(mktemp -d)
export KUBECONFIG="$work/kubeconfig"
k=kubectl

# The cluster is deleted only once this run has created it; until then only
# the work directory is ours.
trap 'rm -rf "$work"' EXIT
cleanup() { kind delete cluster --name "$name" >/dev/null 2>&1 || true; rm -rf "$work"; }

cat > "$work/policy.yaml" <<'EOF'
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages: ["RequestReceived"]
rules:
  - level: Metadata
    resources:
      - group: ""
        resources: ["secrets", "configmaps"]
  - level: Request
    verbs: ["create", "update", "patch", "delete"]
  - level: Metadata
EOF

cat > "$work/kind.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
        audit-log-path: /var/log/kubernetes/kube-apiserver-audit.log
        audit-policy-file: /etc/kubernetes/policies/audit-policy.yaml
        audit-log-maxsize: "500"
      extraVolumes:
        - name: audit-policies
          hostPath: /etc/kubernetes/policies
          mountPath: /etc/kubernetes/policies
          readOnly: true
          pathType: DirectoryOrCreate
        - name: audit-logs
          hostPath: /var/log/kubernetes
          mountPath: /var/log/kubernetes
          readOnly: false
          pathType: DirectoryOrCreate
  extraMounts:
  - hostPath: $work/policy.yaml
    containerPath: /etc/kubernetes/policies/audit-policy.yaml
    readOnly: true
- role: worker
EOF

echo "capture: creating kind cluster $name" >&2
kind create cluster --name "$name" --config "$work/kind.yaml" --kubeconfig "$KUBECONFIG" >&2
trap cleanup EXIT
$k wait --for=condition=Ready nodes --all --timeout=180s >&2

echo "capture: running the workload" >&2
{
    for ns in shop billing batch; do $k create ns "$ns"; done
    $k -n shop create deployment web --image=nginx:1.27-alpine --replicas=3
    $k -n shop expose deployment web --port=80
    $k -n shop create deployment cart --image=busybox:1.36 --replicas=2 -- sh -c 'while true; do echo tick; sleep 5; done'
    $k -n shop create deployment broken --image=registry.invalid/nope/missing:v9
    $k -n billing create deployment crasher --image=busybox:1.36 -- sh -c 'echo boom; exit 3'
    $k -n billing create configmap rates --from-literal=vat=25 --from-literal=currency=SEK
    $k -n billing create secret generic api-key --from-literal=token=invented-not-real-123
    $k -n batch create job once --image=busybox:1.36 -- sh -c 'echo done'
    $k -n batch create cronjob tick --image=busybox:1.36 --schedule='* * * * *' -- sh -c 'date'
    $k -n batch create job fails --image=busybox:1.36 -- sh -c 'exit 1'
    $k -n shop create sa reader
    $k -n shop create role pod-reader --verb=get,list,watch --resource=pods
    $k -n shop create rolebinding reader-pods --role=pod-reader --serviceaccount=shop:reader
    $k -n shop rollout status deployment/web --timeout=180s
    $k -n shop rollout status deployment/cart --timeout=120s
    $k -n shop autoscale deployment web --min=2 --max=6 --cpu=70%

    reader=system:serviceaccount:shop:reader
    for r in secrets deployments configmaps nodes; do $k -n shop --as="$reader" get "$r" || true; done
    $k -n billing --as="$reader" get pods || true
    $k -n shop --as="$reader" delete pod -l app=web || true
    $k -n shop --as="$reader" get pods -o name

    $k -n shop get pod does-not-exist || true
    $k -n nowhere get deploy x || true
    $k get widgets || true
    printf 'apiVersion: v1\nkind: Pod\nmetadata: {name: Bad_Name}\nspec: {containers: [{name: c, image: busybox}]}\n' | $k -n shop apply -f - || true

    $k -n shop set image deployment/web nginx=nginx:1.28-alpine
    $k -n shop rollout status deployment/web --timeout=180s
    $k -n shop scale deployment web --replicas=5
    $k -n shop rollout undo deployment/web
    $k -n shop rollout restart deployment/cart
    $k -n shop label pods -l app=cart tier=backend
    $k -n shop annotate deployment web owner=team-a
    $k -n shop patch deployment web -p '{"spec":{"template":{"metadata":{"labels":{"rev":"2"}}}}}'
    $k -n shop rollout status deployment/web --timeout=180s

    pod=$($k -n shop get pods -l app=web --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')
    $k -n shop exec "$pod" -- nginx -v || true
    $k -n shop exec "$pod" -- ls /nope || true
    $k -n shop logs "$pod" --tail=3 || true
    $k -n shop logs deploy/cart --since=1m || true
    $k -n billing logs deploy/crasher --previous || true
    $k get pods -A --field-selector=status.phase!=Running
    $k get pods -A -l 'app in (web,cart)' --chunk-size=3
    $k -n shop get events --sort-by=.lastTimestamp
    $k -n shop describe deployment broken
    $k top pods -A || true
    $k -n shop delete pod "$pod" --wait=false
    $k -n shop get pods -w --request-timeout=5s || true
    $k cordon "$name-worker"
    $k drain "$name-worker" --ignore-daemonsets --delete-emptydir-data --timeout=90s || true
    $k uncordon "$name-worker"
    $k -n billing delete secret api-key
    $k -n billing delete configmap rates
    $k delete ns batch --wait=false
    sleep 60
} >/dev/null 2>&1

docker exec "$name-control-plane" cat /var/log/kubernetes/kube-apiserver-audit.log > "$out"
echo "capture: $(wc -l < "$out") audit lines in $out" >&2
