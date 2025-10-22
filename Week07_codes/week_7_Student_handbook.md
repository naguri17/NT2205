# Week 7 — Student Handbook (copy‑ready)

**Focus**: Containers on OpenStack (multi‑tenant PaaS on shared hosts). This handout is optimized for **copy/paste** during lab. Replace placeholders like `<VM_NAME>`, `<EXPORT>`, `ghcr.io/yourorg`.

> **Tip**: Keep a terminal log. Paste brief **evidence** under each Notes block (command output, URLs, error snippets).

---

## 0) Quick environment sanity checks

```bash
# OpenStack auth loaded?
openstack token issue -f value -c id

# Swift + account info
swift stat -v | sed -n 's/^Account: //p; s/^StorageURL: //p'

# Docker engine present?
docker version --format '{{.Server.Version}}'

# Ansible (and docker SDK for community.docker)
ansible --version
python3 -c "import docker; print('docker SDK OK')" || pip3 install docker
```

**Notes:**

```ini
Who/where am I running? ______________________________
Token/Account OK? ____________________________________
Docker & Ansible versions _____________________________
```

---

## 1) OpenStack Storage Labs (Block / Object / File)

### A) Cinder — create, attach, format, mount

```bash
# 1) Inspect types & quotas
openstack volume type list
openstack limits show --absolute | grep VOLUME

# 2) Create volume (10GiB on a specific type/AZ)
openstack volume create --size 10 --type lvmdriver --availability-zone nova demo-vol
openstack volume show demo-vol -f table

# 3) Attach to a VM (from controller)
openstack server add volume <VM_NAME> demo-vol

# --- inside the VM ---
lsblk
sudo mkfs.ext4 /dev/vdb
sudo mkdir -p /data && sudo mount /dev/vdb /data

# 4) Persist mount (optional)
echo "/dev/vdb /data ext4 defaults 0 0" | sudo tee -a /etc/fstab
```

**Notes:**

```ini
Device name __________  AZ/type __________  Mount path __________
```

### B) Swift — public URL flow (demo)

```bash
# 1) Create container + upload
openstack container create demo-container
openstack object create demo-container report.pdf

# 2) Public-read container
openstack container set --public demo-container

# 3) Construct URL and check
SWIFT_URL=$(swift stat -v | awk -F': ' '/StorageURL/ {print $2}')
curl -I "$SWIFT_URL/demo-container/report.pdf"
```

**Notes:**

```ini
StorageURL ________________________  HTTP status ______
```

### C) Swift — Temp URL (private, time‑limited)

```bash
# 1) Set an account-level key
KEY=$(openssl rand -hex 16)
openstack object store account set --property Temp-URL-Key="$KEY"

# 2) Gather account & storage URL
ACCOUNT=$(swift stat -v | awk -F': ' '/Account/ {print $2}')
SWIFT_URL=$(swift stat -v | awk -F': ' '/StorageURL/ {print $2}')

# 3) Generate signature (3600 seconds)
SIG=$(swift tempurl GET 3600 "/v1/$ACCOUNT/demo-container/report.pdf" "$KEY")

# 4) Use it
curl -I "$SWIFT_URL/demo-container/report.pdf?$SIG"
```

**Notes:**

```ini
Expiry ______  Signed URL (paste) __________________________________________
```

### D) Manila — NFS share, allow, mount

```bash
# 1) Create share
openstack share create nfs 10 --name demo-share
openstack share show demo-share -f table

# 2) Allow access (adjust your VM’s IP)
openstack share access allow demo-share ip 192.168.1.10

# 3) Mount from VM
sudo apt-get update && sudo apt-get install -y nfs-common
sudo mkdir -p /mnt/share
# Replace <EXPORT> with 'server:/export/path' from "share show"
sudo mount -t nfs <EXPORT> /mnt/share
```

**Notes:**

```ini
Export path __________________  Allowed IP __________  Mount OK? ___
```

---

## 2) VM vs Container — quick recall (for short answers)

- **VM:** dedicated guest kernel; isolation at **hypervisor**; strong isolation; higher resource overhead; slower boot.
- **Container:** shared host kernel; isolation via **namespaces + cgroups** (hardened by capabilities/seccomp/LSMs); fast start; high density; larger shared‑kernel attack surface → **defense‑in‑depth** required.

**Notes:**

```ini
One example where VM is preferred: _________________________________
One example where container is preferred: ___________________________
```

---

## 3) Multi‑stage Dockerfile (Node.js) — copy & adapt

```dockerfile
# Build stage (needs dev deps)
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# (Optional) deps stage to create prod-only node_modules
FROM node:20-alpine AS deps
WORKDIR /src
COPY package*.json ./
RUN npm ci --omit=dev

# Runtime stage (distroless)
FROM gcr.io/distroless/nodejs20-debian12
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=deps /src/node_modules ./node_modules
USER 10001:10001
ENV NODE_ENV=production
EXPOSE 3000
# Distroless has no shell; prefer an app-level /health endpoint
CMD ["dist/server.js"]
```

**Notes:**

```ini
App port ______  Health path (if any) __________  Image ref __________
```

---

## 4) Ansible — install Docker on an OpenStack VM (idempotent)

```yaml
# playbooks/install-docker.yml
- hosts: app_vms
  become: true
  tasks:
    - name: Ensure tooling and Python docker SDK
      package:
        name:
          - curl
          - ca-certificates
          - gnupg
          - lsb-release
          - python3-pip
        state: present
    - name: Install docker SDK for community.docker
      ansible.builtin.pip:
        name: docker
        state: present
    - name: Add Docker apt repo (Debian/Ubuntu)
      shell: |
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/$(. /etc/os-release; echo $ID)/gpg \
          | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/$(. /etc/os-release; echo $ID) \
        $(. /etc/os-release; echo $VERSION_CODENAME) stable" \
          | tee /etc/apt/sources.list.d/docker.list > /dev/null
        apt-get update
        apt-get install -y docker-ce docker-ce-cli containerd.io
      args: { creates: /etc/apt/sources.list.d/docker.list }
    - name: Enable and start Docker
      service:
        name: docker
        state: started
        enabled: yes
```

**Notes:**

```ini
Inventory group used __________  OS family __________  Success? ___
```

---

## 5) Ansible — build & push image to your registry

```yaml
# playbooks/build-push.yml
- hosts: app_vms
  become: true
  vars:
    registry: "ghcr.io/yourorg"
    image_name: "wk7-sample"
    image_tag: "v1"
  tasks:
    - name: Sync app sources
      ansible.posix.synchronize:
        src: ./app/
        dest: /opt/app/
    - name: Build image (local)
      community.docker.docker_image:
        name: "{{ registry }}/{{ image_name }}:{{ image_tag }}"
        build:
          path: /opt/app
        push: false
    - name: Login
      community.docker.docker_login:
        registry_url: "{{ registry }}"
        username: "{{ reg_user }}"
        password: "{{ reg_pass }}"
    - name: Push image
      community.docker.docker_image:
        name: "{{ registry }}/{{ image_name }}:{{ image_tag }}"
        push: true
```

**Notes:**

```ini
Registry __________  Tag __________  Image digest (sha256) __________
```

---

## 6) Ansible — run container with limits & healthcheck

```yaml
# playbooks/run-with-limits.yml
- hosts: app_vms
  become: true
  tasks:
    - name: Run container with resource limits and healthcheck
      community.docker.docker_container:
        name: wk7-web
        image: "ghcr.io/yourorg/wk7-sample:v1"
        state: started
        published_ports:
          - "80:3000"
        restart_policy: unless-stopped
        memory: "512m"
        cpus: "0.5"
        env:
          NODE_ENV: production
        healthcheck:
          test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
          interval: 30s
          timeout: 3s
          retries: 3
          start_period: 10s
```

**Notes:**

```ini
Endpoint OK? ______  p95 latency note __________  Resource limits OK? ___
```

---

## 7) Hardening quick checks (copy/paste + capture evidence)

### Image & execution

```bash
# Non-root?
docker inspect wk7-web --format '{{.Config.User}}'

# Caps dropped? (may be empty when all dropped)
docker inspect wk7-web --format '{{json .HostConfig.CapDrop}}' | jq .

# Seccomp profile attached? (path or "default")
docker inspect wk7-web --format '{{.HostConfig.SecurityOpt}} {{.HostConfig.SeccompProfile}}'

# Read-only rootfs?
docker inspect wk7-web --format '{{.HostConfig.ReadonlyRootfs}}'

# SBOM + signature (if available)
syft "{{IMAGE_REF}}" -o table | head -20
cosign verify "{{IMAGE_REF}}"
```

**Notes:**

```ini
User=_____  CapDrop=_____  Seccomp=_____  ROFS=_____  SBOM/signature=_____
```

### Runtime & ops

```bash
# CPU/mem/PIDs effective?
docker stats --no-stream
cat /sys/fs/cgroup/pids.max 2>/dev/null || true

# Logs & basic audit
docker logs wk7-web | tail -n +1 | wc -l
dmesg | tail -n 50 | sed -n '/apparmor\|selinux/p'
```

**Notes:**

```ini
SLO observation (p95/99) _________________________________________________
```

---

## 8) Networking quick refs (docker)

```bash
# Port mapping & verification
docker ps --format 'table {{.Names}}\t{{.Ports}}'
curl -I http://localhost:80/health

# Identify network & inspect
docker network ls
docker network inspect bridge | jq '.[0].IPAM.Config'
```

**Notes:**

```ini
MTU/hairpin issues? ________________________________________________
```

---

## 9) Common pitfalls (checklist)

- Floating tags (`:latest`) → **pin `@sha256`**.
- Running as root + RW bind mount → **EoP risk**.
- `overlay2` + random write workload → **use bind‑mount or block volume** for hot paths.
- Missing healthcheck → **no early rollback signal**.
- Saying “Docker” when you mean Swarm vs Engine → **be explicit**.

**Notes:**

```ini
Your team's gotchas: _________________________________________________
```

---

## 10) Turn‑in (what to capture)

- **Screenshots:** Docker installed; image in registry; `docker ps`; public/Temp‑URL curl headers.
- **Files:** `Dockerfile`, `playbooks/*.yml`, inventory, (optional) `docker-compose.yml`.
- **Short report (≤2 pages):** VM vs Container (perf & security), your deployment diagram, test results.

---

### (Optional) Minimal `docker-compose.yml` for local dev
>
> Compose doesn’t enforce CPU/mem limits outside Swarm; use it for wiring only.

```yaml
version: "3.9"
services:
  web:
    image: ghcr.io/yourorg/wk7-sample:v1
    ports: ["80:3000"]
    environment:
      NODE_ENV: production
```

**Notes:**

```ini
Local only? yes/no  Service reachable? _____
```
