---
name: virtualization-operations
description: Design, inspect, and reset isolated Docker or virtual-machine labs while reasoning accurately about kernels, namespaces, virtual networks, mounts, storage, and experiment boundaries. Use for containerized infrastructure labs, multi-node networking, reproducible fault injection, and virtualization resource planning.
---

# Virtualization operations

Use this skill when building or diagnosing a local virtualized infrastructure lab, especially one with multiple Docker containers and virtual networks.

## Establish the runtime boundary

1. Identify whether the environment uses containers, full VMs, or both. Containers share the host kernel; do not describe them as separate guest kernels.
2. Read the project setup and teardown scripts before running them. Confirm resource names and identify what is persistent outside the container writable layer.
3. Inspect Docker daemon state, image IDs, container status, mounts, capabilities, ports, and network attachments. Use the current runtime state instead of assuming a prior IP or name mapping.
4. State the isolation property actually established. An internal bridge or lack of published ports does not prove the host cannot inspect or reach the containers.

## Model the topology

Represent each container network as a graph. Record the members and addresses on each bridge, aliases, routes, and which nodes have multiple interfaces. Distinguish direct virtual-network adjacency from application-level paths such as SSH `ProxyJump`. A multi-homed container does not automatically forward IP packets between attached networks.

Useful read-only commands:

```sh
docker ps --format '{{.Names}} {{.Status}}'
docker inspect <container>
docker network inspect <network>
docker stats --no-stream
docker system df
```

Use `sudo` only when the configured Docker access requires it. Avoid printing credentials or private key material into logs.

## Make experiments reproducible

- Pin or record image digests when image drift matters.
- Use project-specific container, network, and volume names.
- Reset by recreating only owned resources; never use global prune commands as routine cleanup.
- Restore host-side bind-mounted fixtures explicitly; deleting a container does not reset bind mounts or named volumes.
- Reset service logs along with container state when the experiment assumes clean evidence.
- Serialize trials that share mutable containers, or allocate a separate project, network, client directory, and trace directory per worker.
- Record prompt, model/request identifiers, topology, fault, tool calls, exact changes, and verification result.

## Plan disk and memory

Treat host filesystem free space and Docker storage capacity as separate measurements. `df -h` for the working directory may refer to a different filesystem than Docker's data root. Check `docker info` and `docker system df`. Estimate memory from live measurements (`docker stats`, host memory tools) rather than assuming a fixed per-container cost. Keep headroom for image builds and concurrent jobs.

## Safety and reporting

Before a reset, inspect the exact targets and make sure they belong to the lab. Keep production and personal resources outside the lab namespace. After a reset, verify that the intended containers and network graph exist and that the baseline service path works. Report what was measured and what remains an assumption; do not claim VM-level isolation from container-only evidence.
