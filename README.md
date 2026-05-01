# harden-docker-seccomp

Idempotent script to block `AF_ALG` socket creation for all Docker containers
on a host as mitigation for **CVE-2026-31431** ("Copy Fail").

## Background

CVE-2026-31431 is a local privilege escalation in the Linux kernel's
`authencesn` cryptographic template, present in kernels built between 2017 and
the availability of the upstream fix (mainline commit `a664bf3d603d`). An
unprivileged user can chain an `AF_ALG` socket operation with `splice()` to
perform a controlled 4-byte write into the page cache of any readable file,
targeting a setuid binary to obtain a root shell. A 732-byte Python proof of
concept exploits this reliably, without races or per-distro offsets, on every
major Linux distribution shipping an affected kernel.

The exploit's mandatory first step is opening an `AF_ALG` socket
(`socket(AF_ALG, SOCK_SEQPACKET, 0)`). Blocking that syscall via seccomp
prevents exploitation even on unpatched kernels. Docker's built-in default
seccomp profile does not block `AF_ALG`, and `RuntimeDefault` is not
sufficient — tested clusters showed that pods admitted under PSS Restricted
could still open `AF_ALG` sockets.

See the original researcher advisory at <https://copy.fail> and the CERT-EU
advisory at <https://cert.europa.eu/publications/security-advisories/2026-005/>
for full technical detail and patch availability by distribution.

### Scope of this tool

This script covers the Docker Engine global daemon configuration. For
Kubernetes, see the [Kubernetes section](#kubernetes) below. For bare-metal or
VM workloads (non-containerised), disable the `algif_aead` kernel module
instead:

```sh
echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif.conf
rmmod algif_aead 2>/dev/null || true
```

That approach has no impact on dm-crypt/LUKS, kTLS, IPsec/XFRM, OpenSSL,
GnuTLS, NSS, or SSH.

## How it works

1. **Extracts Docker's active built-in seccomp profile** by inspecting a
   short-lived container's `HostConfig.SecurityOpt`. This avoids any
   dependency on a remote URL and guarantees the base profile matches the
   Docker version actually installed. A GitHub fetch from
   [`moby/profiles`](https://github.com/moby/profiles) is used as a fallback
   only if container inspection yields nothing.

2. **Patches the profile** by removing `socket` from Docker's allowlist entry
   and re-adding it with an argument filter that allows all address families
   except `AF_ALG` (value `38`) using `SCMP_CMP_NE`. All other Docker default
   seccomp behaviour is preserved.

3. **Writes the patched profile** atomically to
   `/etc/seccomp/docker-block-af-alg.json` (temp file + rename). Skipped if
   the on-disk content is already identical.

4. **Updates `/etc/docker/daemon.json`** to set `"seccomp-profile"` to the
   patched profile path. The original file is backed up to `daemon.json.bak`
   on first modification. Skipped if already configured correctly.

5. **Reloads `dockerd`** via `systemctl reload docker` (SIGHUP — no restart
   required). Skipped if neither file changed.

6. **Verifies the block is active** by running a probe inside a container,
   regardless of whether any changes were made in the steps above.

The script is idempotent: running it multiple times produces the same result
and only reloads Docker when something actually changed.

> **Note:** `--privileged` containers bypass all seccomp profiles regardless
> of this configuration. Audit your Compose files and run commands for
> privileged containers separately.

## Requirements

- Python 3.12+
- Docker Engine (not Docker Desktop) running on the host
- `docker` CLI in `PATH`
- `curl` in `PATH` (fallback only)
- `systemctl` (systemd host)
- Root / sudo for writes to `/etc/seccomp` and `/etc/docker`, and for
  `systemctl reload docker`

## Usage

```sh
# Apply the mitigation and verify (normal usage)
sudo python3 harden-docker-seccomp.py

# Show what would change without writing anything or reloading Docker
sudo python3 harden-docker-seccomp.py --dry-run

# Re-run the container verification only (no config changes)
python3 harden-docker-seccomp.py --verify-only

# Verbose output
sudo python3 harden-docker-seccomp.py --verbose
```

### Expected output (first run)

```text
INFO Written: /etc/seccomp/docker-block-af-alg.json
INFO Updated: /etc/docker/daemon.json
INFO Reloading Docker daemon (SIGHUP)…
INFO Docker daemon reloaded.
INFO Verifying AF_ALG is blocked inside a container…
OK: AF_ALG blocked — [Errno 1] Operation not permitted
INFO All done. CVE-2026-31431 (Copy Fail) mitigation is active.
```

### Expected output (subsequent runs)

```text
INFO Profile unchanged: /etc/seccomp/docker-block-af-alg.json
INFO daemon.json already configured correctly.
INFO No changes — Docker daemon reload not required.
INFO Verifying AF_ALG is blocked inside a container…
OK: AF_ALG blocked — [Errno 1] Operation not permitted
INFO All done. CVE-2026-31431 (Copy Fail) mitigation is active.
```

## Exit codes

| Code | Meaning |
| ---- | ------- |
| `0`  | Success — mitigation is active |
| `1`  | Script not run as root (when patching), or unrecoverable error |
| `2`  | Verification failed — `AF_ALG` is not blocked |

## Kubernetes

Kubernetes pods share the host kernel, so the same `AF_ALG` socket primitive
is reachable from any pod on an affected node. `RuntimeDefault` seccomp is not
sufficient — tested clusters showed that pods admitted under PSS Restricted
could still open `AF_ALG` sockets. A `Localhost` profile with an explicit deny
rule is required.

Mitigation requires two things: the profile JSON present on every node's
filesystem, and every pod spec referencing it. The sections below cover both,
including how to inject the profile globally without modifying individual pod specs.

### Step 1 — Distribute the profile to every node

The kubelet resolves `Localhost` seccomp profiles relative to its seccomp
root, which defaults to `/var/lib/kubelet/seccomp`. The profile must exist at
that path on every node that may schedule a workload.

Apply the ConfigMap and DaemonSet from this repository:

```sh
kubectl apply -f templates/configmap-seccomp-profile.yaml
kubectl apply -f templates/daemonset-distribute-profile.yaml
```

The DaemonSet runs an init container that copies the profile from the
ConfigMap to the node's kubelet seccomp root, then parks a minimal pause
container so the pod remains visible for health monitoring. It tolerates all
taints so it also runs on control-plane nodes.

> **Non-standard kubelet seccomp root:** RKE2 uses
> `/var/lib/rancher/rke2/agent/kubelet/seccomp`. Override the path by setting
> `NODE_SECCOMP_ROOT` in the DaemonSet's init container env before applying.

Verify the file is present on a node:

```sh
kubectl -n kube-system exec -it \
  $(kubectl -n kube-system get pod -l app.kubernetes.io/name=distribute-af-alg-seccomp \
    -o jsonpath='{.items[0].metadata.name}') -- \
  cat /var/lib/kubelet/seccomp/block-af-alg.json
```

### Step 2 — Inject the profile into every pod (no pod-spec changes required)

Rather than modifying individual pod specs or Helm charts, use a mutating
admission webhook to inject `seccompProfile` automatically at admission time.
Two options are provided: Kyverno and OPA Gatekeeper.

Both approaches only inject the profile when a pod does not already declare
one, so pods with explicit profiles are left untouched.

> **Important:** Existing running pods are not retroactively mutated. After
> applying the policy, roll your deployments to pick up the injected profile:
>
> ```sh
> kubectl rollout restart deployment -A
> ```

#### Option A — Kyverno

This template uses the `MutatingPolicy` API (`policies.kyverno.io/v1`),
which reached GA in Kyverno 1.17. The legacy `ClusterPolicy` API
(`kyverno.io/v1`) was deprecated in Kyverno 1.17 (January 2026) and is
planned for removal in 1.20 (October 2026); do not use it for new policies.

The `matchConditions` CEL expression checks that `seccompProfile` is absent
before mutating, so pods that already declare a profile are left untouched.

```sh
# Install Kyverno (if not already present)
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm upgrade --install kyverno kyverno/kyverno -n kyverno --create-namespace

# Apply the policy
kubectl apply -f templates/kyverno-mutate-seccomp.yaml
```

Verify a new pod receives the injected profile:

```sh
kubectl run test --image=busybox --restart=Never -- sleep 30
kubectl get pod test -o jsonpath='{.spec.securityContext.seccompProfile}'
# Expected: {"localhostProfile":"block-af-alg.json","type":"Localhost"}
kubectl delete pod test
```

See [`templates/kyverno-mutate-seccomp.yaml`](templates/kyverno-mutate-seccomp.yaml).

#### Option B — OPA Gatekeeper

Gatekeeper's `Assign` mutation CRD uses a `pathTests` condition to inject the
profile only when `spec.securityContext.seccompProfile` does not already exist.
Mutation has been stable since Gatekeeper 3.10+; no feature flag is required.

```sh
# Install Gatekeeper (if not already present)
helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts
helm repo update
helm install -n gatekeeper-system gatekeeper gatekeeper/gatekeeper \
  --create-namespace

# Apply the mutation
kubectl apply -f templates/gatekeeper-assign-seccomp.yaml
```

Verify:

```sh
kubectl run test --image=busybox --restart=Never -- sleep 30
kubectl get pod test -o jsonpath='{.spec.securityContext.seccompProfile}'
# Expected: {"localhostProfile":"block-af-alg.json","type":"Localhost"}
kubectl delete pod test
```

See [`templates/gatekeeper-assign-seccomp.yaml`](templates/gatekeeper-assign-seccomp.yaml).

> **Gatekeeper vs. Kyverno:** The `Assign` approach operates at the field
> level and requires the Gatekeeper mutation webhook to be enabled. Kyverno's
> `MutatingPolicy` with a CEL `matchCondition` handles the conditional inline.
> Either achieves the same result — prefer whichever is already deployed in
> your cluster.

### What this does not cover

Pods with `hostPID: true`, `hostNetwork: true`, or
`securityContext.privileged: true` have elevated access that seccomp alone does
not fully contain. Audit those workloads separately and remove privilege where
possible.

### Template design notes

**ConfigMap as source of truth.** The profile JSON lives in
`configmap-seccomp-profile.yaml` rather than being embedded in the DaemonSet
or duplicated across files. The DaemonSet mounts it and copies it to the node.
Updating the profile means editing one ConfigMap and restarting the DaemonSet
pods — no other files change.

**DaemonSet uses `system-node-critical` priority.** This ensures the
distribution pod is not evicted before the workloads it protects are scheduled,
which would leave nodes with a missing profile file and pods stuck in
`CreateContainerError`.

**Gatekeeper excludes `kube-system` and `gatekeeper-system`.** Injecting a
`Localhost` profile into system pods that may predate the DaemonSet
installation risks a broken profile reference if the file is not yet present on
the node. The Kyverno policy does not need this exclusion because Kyverno
handles webhook ordering more gracefully, but `exclude` rules can be added
there too if needed.

**Conditional injection, not override.** Both the Kyverno `MutatingPolicy`
CEL `matchCondition` and the Gatekeeper `MustNotExist` path test mean the
admission policy only acts when a pod has no existing `seccompProfile`.
Workloads that already declare their own profile — including those that
legitimately need `AF_ALG` via a custom allow-list — are left untouched.

## References

- <https://copy.fail> — Original researcher advisory (Xint)
- <https://cert.europa.eu/publications/security-advisories/2026-005/> — CERT-EU advisory
- <https://www.cve.org/CVERecord?id=CVE-2026-31431> — CVE record
- <https://security-tracker.debian.org/tracker/CVE-2026-31431> — Debian security tracker
- <https://docs.docker.com/engine/security/seccomp/> — Docker seccomp documentation
- <https://github.com/moby/profiles> — Canonical Docker default seccomp profile
- <https://kyverno.io/docs/kyverno-policies/> — Kyverno policy documentation
- <https://open-policy-agent.github.io/gatekeeper/website/docs/mutation/> — Gatekeeper mutation documentation

## Yeah, Claude did most of the work, here's the chat

<https://gist.github.com/devstuff/3ff3ca0139e2a2da7f1ee5875802f76f>
