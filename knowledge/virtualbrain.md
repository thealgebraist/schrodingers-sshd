# Virtualization and isolated lab operations

This document records the operating model and lessons from building and running a multi-hop SSH diagnosis lab with Docker. It is a practical reference for designing small reproducible infrastructure experiments. It distinguishes container behavior observed in this lab from broader conclusions that would need measurement on another host or runtime.

## 1. Start with the correct abstraction

Docker containers are isolated processes that share the host kernel. They are not separate hardware machines and are not, by themselves, full virtual machines. A container image supplies a filesystem and launch configuration; the runtime constructs namespaces, applies resource controls, mounts filesystems, configures networking, and starts the process. The host kernel still services system calls made by every container.

This distinction matters when interpreting a benchmark. A container gives useful process, filesystem, and network separation for controlled experiments, but it does not prove the behavior of a different kernel, hypervisor, cloud network, or physical host. A container escape or a privileged container changes the trust boundary. Do not describe an internal Docker network as a complete security boundary against the host or Docker daemon.

Use a VM when the experiment needs a separately booted guest kernel, guest kernel modules, kernel-version differences, or a stronger isolation boundary. Use containers when the question concerns application processes, userspace tools, service configuration, TCP reachability, SSH behavior, repeatable filesystems, or network paths that can be modeled with separate namespaces and virtual bridges.

## 2. The layers to reason about

An infrastructure test commonly crosses these layers:

1. **Host and runtime:** Docker daemon availability, image cache, storage driver, bridge creation, permissions, CPU and memory pressure.
2. **Image:** OS userspace, installed packages, entrypoint, default configuration, and build provenance.
3. **Container instance:** writable layer, process tree, environment, mounts, capabilities, limits, and lifecycle state.
4. **Virtual network:** network namespace interfaces, addresses, routes, DNS aliases, bridge membership, internal-network policy, and published ports.
5. **Application protocol:** listener state, authentication, forwarding, session creation, and remote command behavior.
6. **Test harness:** prompt, tool allowlist, request history, reset policy, captured output, and success criteria.

An observed failure at a later layer usually implies some earlier work occurred, but a single client-facing error is not enough to identify the exact layer. For example, an SSH public-key denial usually implies that a TCP connection reached an SSH service, while a timeout may occur before the SSH protocol starts. A valid host key from `ssh-keyscan` establishes that an SSH server answered the scan; it does not prove user authentication or remote command access.

## 3. Docker storage and lifecycle

### Images and writable layers

An image is a reusable, layered filesystem plus metadata. Starting a container adds an instance-specific writable layer. Removing the container discards changes in that layer. Rebuilding an image does not mutate containers already created from an earlier image ID; newly created containers use the selected image.

This gives a useful experimental reset mechanism: recreate the containers from a known image to restore files, process state, and container logs. Verify the image ID or digest if image changes matter. Reusing a long-lived container is not equivalent to a fresh run because it may preserve altered configuration, added files, process state, or accumulated logs.

### Bind mounts and volumes

A bind mount maps a host path into a container. Its data is outside the container writable layer and survives container deletion. A read-only mount prevents writes through that mount from the container, but the host-side file can still be changed by the harness or operator. A Docker-managed volume also persists beyond a container's lifetime until the volume is explicitly removed.

In the SSH lab, the client `.ssh` directory is mounted read-only into the client container. The agent can read and use the key and configuration but cannot edit them from inside that mount. The repair tool changes the host-side config file directly. The server image mounts the lab's public `authorized_keys` input read-only and the entrypoint copies it into each new container's writable home directory with a defined owner and mode. As a result, changing a server's copied key file is discarded by container recreation, while the source fixture persists.

Before claiming that a reset is complete, enumerate every persistent input: bind mounts, named volumes, host configuration, generated credentials, Docker networks, images, and external services. Resetting the container alone does not reset those inputs.

### Avoid accidental collateral resets

Reset scripts should name only resources owned by the lab. Prefer a project-specific prefix for containers, networks, volumes, and images. Inspect the target resource names before removal. Avoid global prune commands: they can remove unrelated developer or production state. Keep setup and teardown commands visible and explicit.

In this workspace, the eight-server reset script removes only the `mh-*` containers and its named `mh-*` networks, recreates them, and restores the client config and private-key mode from a baseline file. The four-server preparation helper currently uses that reset, then stops servers 5–8 and injects a fault on server2. It recreates containers before each trial, so the filesystem changes and logs inside those server containers are fresh.

## 4. Network namespaces and virtual topology

Each container has a network namespace. A Docker bridge network connects the interfaces attached to that network. Containers attached to a shared user-defined bridge can generally communicate directly by address and, with network aliases, by service name. A container attached to multiple networks can communicate on each attached segment; this does not automatically mean that it forwards arbitrary packets between those networks.

The SSH test topology uses one bridge per adjacent link:

```text
client — server1 — server3 — server2 — server4 — server5 — server6 — server7 — server8
```

The four-server experiment uses the prefix ending at server4. Server1, server3, server2, and server4 each have only the network attachments needed for their neighboring links. SSH `ProxyJump` creates application-level forwarding sessions along the path. The Docker bridge graph and SSH jump graph are related but not identical: Docker provides direct links; the SSH client composes those links into an end-to-end route.

An `--internal` bridge is configured to restrict external connectivity through that network. It is useful for labs that should not expose service ports to the outside. It does not mean “the Docker host cannot inspect or control these containers,” and it should not be used as a substitute for host firewalling or daemon security. Check `docker network inspect` and container attachments rather than assuming the intended topology from names alone.

Use static addressing only when it improves reproducibility. Otherwise discover addresses from runtime inspection, because recreated bridges may allocate different addresses. Network aliases are scoped to the network and may resolve differently depending on which container asks. Never infer that two names resolve to one global host merely because they are aliases in a compose file.

Useful inspection commands include:

```sh
sudo docker ps --format '{{.Names}} {{.Status}}'
sudo docker inspect <container>
sudo docker network inspect <network>
sudo docker logs --tail 100 <container>
sudo docker exec <container> ip addr
sudo docker exec <container> ip route
```

Inspect the result format and the network namespace that owns each address. A host's route table is not a substitute for a container's route table.

## 5. Isolation is a measured property

“Isolated” can refer to multiple different boundaries:

- no published host port;
- no route from a container network to the public internet;
- no access to unrelated host services;
- no ability to contact other containers;
- no access to host files or devices;
- no access to the container runtime socket;
- no persistent state between trials.

Prove the relevant property separately. For example, inspect port bindings to establish whether a service port is published; inspect bridge flags and routes for network egress; inspect mounts and capabilities for host access; use connection attempts for an application-level assertion. A private bridge does not prove that no other host process can reach it. A fresh container does not prove that logs in an external collector were cleared.

The lab does not publish SSH ports to the host and uses internal bridges. The operator can still inspect and control it through Docker and `sudo`. This is appropriate for a local test harness, not a hostile multi-tenant sandbox.

## 6. Resource planning for multiple nodes

Memory use depends on the image, running processes, page cache, and runtime overhead. A small Debian SSH daemon container is much lighter than a full desktop VM, but do not infer an exact per-node budget from the number of containers. Measure with `docker stats`, host memory tools, and the actual number of simultaneous test jobs. Reserve headroom for image builds, response logs, and concurrent API processes.

Disk is a separate constraint. `df -h .` reports filesystem capacity for the current path, but it does not describe Docker's storage root if that path is on a different filesystem. Check `docker info`, `docker system df`, and the mount containing Docker's data root before estimating capacity. Image layers may be shared; build cache, writable layers, logs, and volumes have different lifetimes. Avoid automated pruning as a routine experiment reset.

Parallel model calls can make a single lab unsafe if they mutate the same containers or client configuration. Either serialize trials or give each worker an isolated project prefix, client directory, Docker network set, and trace directory. A fresh API process alone does not make a shared mutable environment independent.

## 7. Designing a reproducible experiment

Record the full state that can affect the result:

- image tag and immutable image ID or digest;
- container names, status, mounts, users, capabilities, and network attachments;
- addresses, aliases, routes, and published ports;
- service configuration and file owners/modes;
- client configuration, credentials metadata, and command options;
- prompt, model ID, reasoning effort, request bodies, API response IDs, usage, tool calls, and tool results;
- reset method, timestamps, model process boundary, and trial identifier.

Define the success condition before running. For this SSH lab, success is not merely that TCP/22 is reachable: the requested remote `hostname` command must return the expected server name. Keep observations, inferences, changes, and post-change verification separate in the trial record.

Use a clean reset before every model trial. Do not provide the model prior transcripts or a `previous_response_id` if the benchmark is intended to measure independent first-attempt behavior. Record same-trial tool history because it is part of the model's evidence. Preserve full raw API request and response bodies for later analysis, while never logging authorization headers or credentials.

## 8. Lessons from the SSH model experiment

The observed four-server setup has an internal route through server2 to server4. When server2's `authorized_keys` file is mode `0666`, OpenSSH's strict mode check rejects public-key authentication even though the matching public key is present. Server2's log reports bad ownership or modes. This is a good example of state that lives inside a container copy rather than in the read-only source fixture.

Across 20 fresh low-effort GPT-6 Luna Responses API runs with a short generic task prompt and one diagnostic-call limit, no run restored server4 access. Eighteen runs changed the destination alias's `ProxyJump` to bypass server2, which did not restore the path; two attempted ineffective key-related actions. The fault was the server2 file mode. The correct repair in this lab is changing only that file to `0600`, then verifying the route. This result is tied to the exact prompt, tool surface, model, topology, and injected fault; it is not a general estimate of model capability.

The model was asked to provide `response` and `thinking` JSON fields, where `thinking` meant a concise explanation tied to evidence. Some explanations were useful; some asserted that a key was absent even though the inspection output contained the client's public key. A requested rationale is itself model output and must be checked against the raw tool evidence. OpenAI API reasoning summaries are summaries, not a raw transcript of private reasoning tokens.

## 9. Practical checklist

Before a run:

- confirm the exact project-specific containers and networks;
- confirm the target count and graph, not just a familiar container name;
- restore client config, permissions, and server fixtures;
- inject exactly the intended fault and verify it independently;
- confirm the expected control route and failure signature;
- ensure no two workers share the same mutable lab;
- start a fresh model process and trace file.

After a run:

- inspect API request/response logs and tool results;
- score the actual change, not only the final prose;
- verify success using the requested remote command;
- save fault, prompt, result, and limitations in a machine-readable summary;
- restore baseline containers before handing the workspace to the next task.
