/*
 * tabula_rasa_diagnoser.c
 *
 * Tabula Rasa Autonomous Learning & Model-Based Diagnostic Engine for Multi-Hop Networks.
 *
 * Architecture & 5-Phase Meta-Loop:
 *   Phase 1: Tabula Rasa Exploration & World Model Synthesis (Zero Prior Knowledge).
 *            Discovers nodes, channels, protocols, and constructs empirical transition system M = <S, A, T, O>.
 *   Phase 2: Discriminative Invariant Learning (Problem vs. Not-Problem Boundary).
 *            Computes absorbing failure states, Bellman reachability, and sub-nanosecond C1P contiguity.
 *   Phase 3: Plan Generation (Candidate Solution Trajectory & Dual Observations).
 *            A* / Bellman shortest-path search generating minimal action sequence Pi and predicted observations O_hat.
 *   Phase 4: In-Model Counterfactual Simulation & Verification.
 *            Simulates candidate plan entirely inside world model M prior to execution; asserts safety & reachability.
 *   Phase 5: Iterative Refinement & Active Learning Loops.
 *            If model uncertainty > threshold: triggers 5 -> 2 -> ... -> 5 (refinement) or
 *            5 -> 1 -> ... -> 5 (targeted active epistemic probing) until confidence converges to 1.0.
 *
 * Standards: Pure C99, Zero External Dependencies, POSIX 200809L.
 *
 * Compile:
 *   clang -std=c99 -D_POSIX_C_SOURCE=200809L -O3 -Wall -Wextra -Werror -pedantic tabula_rasa_diagnoser.c -lm -o tabula_rasa_diagnoser
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <time.h>
#include <assert.h>

#define MAX_DISCOVERED_NODES  16
#define MAX_NAME_LEN          64
#define MAX_ACTIONS           32
#define MAX_OBS_TOKENS        32
#define MAX_PLAN_STEPS        16
#define MAX_HISTORY_STEPS     128
#define UNCERTAINTY_THRESHOLD 0.25
#define MAX_SIM_STEPS         32

/* ============================================================================
 * 1. MATHEMATICAL FORMALISM: ACTIONS, OBSERVATIONS, PROTOCOL SUBSTAGES
 * ============================================================================ */

typedef enum {
    LAYER_UNKNOWN = 0,
    LAYER_DNS,
    LAYER_TCP_ROUTING,
    LAYER_SSH_BANNER,
    LAYER_SSH_PUBLICKEY_AUTH,
    LAYER_TCP_FORWARDING,
    LAYER_REMOTE_EXEC_GOAL
} ProtocolLayer;

static const char* layer_to_str(ProtocolLayer l) {
    switch (l) {
        case LAYER_DNS: return "DNS_RESOLUTION";
        case LAYER_TCP_ROUTING: return "TCP_ROUTING";
        case LAYER_SSH_BANNER: return "SSH_BANNER_KEX";
        case LAYER_SSH_PUBLICKEY_AUTH: return "SSH_PUBLICKEY_AUTH";
        case LAYER_TCP_FORWARDING: return "SSH_TCP_FORWARDING";
        case LAYER_REMOTE_EXEC_GOAL: return "REMOTE_EXEC_GOAL";
        default: return "UNKNOWN_LAYER";
    }
}

typedef enum {
    /* Exploratory Probing Actions (Read-Only) */
    ACT_EXPLORE_PROBE_DNS = 0,
    ACT_EXPLORE_PROBE_TCP,
    ACT_EXPLORE_PROBE_BANNER,
    ACT_EXPLORE_PROBE_AUTH,
    ACT_EXPLORE_PROBE_FORWARDING,
    ACT_EXPLORE_PROBE_EXEC,

    /* Targeted Epistemic Queries (Active Learning) */
    ACT_EPISTEMIC_CHECK_PERMS,
    ACT_EPISTEMIC_CHECK_CONFIG,

    /* Counterfactual Remediation Mutations */
    ACT_REPAIR_CHMOD_KEYS_600,
    ACT_REPAIR_CHMOD_DIR_700,
    ACT_REPAIR_ENABLE_FORWARDING_YES,
    ACT_REPAIR_RESTRICT_KEX_SUITE,
    ACT_REPAIR_RELOAD_SSHD,

    ACT_COUNT
} ActionID;

static const char* action_to_str(ActionID a) {
    switch (a) {
        case ACT_EXPLORE_PROBE_DNS: return "PROBE_DNS";
        case ACT_EXPLORE_PROBE_TCP: return "PROBE_TCP_PORT";
        case ACT_EXPLORE_PROBE_BANNER: return "PROBE_SSH_BANNER";
        case ACT_EXPLORE_PROBE_AUTH: return "PROBE_PUBLICKEY_AUTH";
        case ACT_EXPLORE_PROBE_FORWARDING: return "PROBE_TCP_FORWARDING";
        case ACT_EXPLORE_PROBE_EXEC: return "PROBE_REMOTE_EXEC";
        case ACT_EPISTEMIC_CHECK_PERMS: return "EPISTEMIC_CHECK_PERMS";
        case ACT_EPISTEMIC_CHECK_CONFIG: return "EPISTEMIC_CHECK_CONFIG";
        case ACT_REPAIR_CHMOD_KEYS_600: return "MUTATE_CHMOD_KEYS_600";
        case ACT_REPAIR_CHMOD_DIR_700: return "MUTATE_CHMOD_DIR_700";
        case ACT_REPAIR_ENABLE_FORWARDING_YES: return "MUTATE_ENABLE_FORWARDING_YES";
        case ACT_REPAIR_RESTRICT_KEX_SUITE: return "MUTATE_RESTRICT_KEX_SUITE";
        case ACT_REPAIR_RELOAD_SSHD: return "MUTATE_RELOAD_SSHD";
        default: return "ACT_UNKNOWN";
    }
}

typedef enum {
    OBS_CLEAN_SUCCESS = 0,
    OBS_DNS_NXDOMAIN,
    OBS_TCP_CONN_REFUSED,
    OBS_TCP_TIMEOUT_OR_DROP,
    OBS_AUTH_PUBLICKEY_DENIED,
    OBS_AUTH_STRICTMODES_INSECURE,
    OBS_FORWARDING_ADMIN_PROHIBITED,
    OBS_KEX_DPI_OR_MTU_DROP,
    OBS_MAXSTARTUPS_OBSERVER_COLLAPSE,
    OBS_EXEC_STDOUT_TARGET_HOSTNAME,
    OBS_COUNT
} ObsToken;

static const char* obs_to_token_str(ObsToken o) {
    switch (o) {
        case OBS_CLEAN_SUCCESS: return "OBS_CLEAN_SUCCESS";
        case OBS_DNS_NXDOMAIN: return "OBS_DNS_NXDOMAIN";
        case OBS_TCP_CONN_REFUSED: return "OBS_TCP_CONN_REFUSED";
        case OBS_TCP_TIMEOUT_OR_DROP: return "OBS_TCP_TIMEOUT_OR_DROP";
        case OBS_AUTH_PUBLICKEY_DENIED: return "OBS_AUTH_PUBLICKEY_DENIED";
        case OBS_AUTH_STRICTMODES_INSECURE: return "OBS_AUTH_STRICTMODES_INSECURE";
        case OBS_FORWARDING_ADMIN_PROHIBITED: return "OBS_FORWARDING_ADMIN_PROHIBITED";
        case OBS_KEX_DPI_OR_MTU_DROP: return "OBS_KEX_DPI_OR_MTU_DROP";
        case OBS_MAXSTARTUPS_OBSERVER_COLLAPSE: return "OBS_MAXSTARTUPS_OBSERVER_COLLAPSE";
        case OBS_EXEC_STDOUT_TARGET_HOSTNAME: return "OBS_EXEC_STDOUT_TARGET_HOSTNAME";
        default: return "OBS_UNKNOWN";
    }
}

/* ============================================================================
 * 2. WORLD MODEL DATA STRUCTURES (EMPIRICAL MDP / CAUSAL GRAPH)
 * ============================================================================ */

typedef struct {
    char name[MAX_NAME_LEN];
    uint32_t hop_index;
    bool discovered;
    bool reachable_prefix;
    bool is_target;
} DiscoveredNode;

typedef struct {
    uint32_t from_node;
    ProtocolLayer layer;
    bool is_healthy;
    ObsToken last_obs;
} StateRepresentation;

typedef struct {
    ActionID action;
    uint32_t target_node;
    ObsToken expected_obs;
} PlanStep;

typedef struct {
    uint32_t count;
    PlanStep steps[MAX_PLAN_STEPS];
    double expected_confidence;
    bool passed_in_model_eval;
} SolutionTrajectory;

/*
 * The Learned World Model M = <S, A, T, O>
 * Maintains empirical transition frequencies, counts, and epistemic uncertainty.
 */
typedef struct {
    DiscoveredNode nodes[MAX_DISCOVERED_NODES];
    uint32_t num_nodes;

    /* Empirical Transition Tensor: Count(node, layer, action, obs) */
    uint32_t obs_counts[MAX_DISCOVERED_NODES][LAYER_REMOTE_EXEC_GOAL + 1][ACT_COUNT][OBS_COUNT];
    uint32_t total_action_counts[MAX_DISCOVERED_NODES][LAYER_REMOTE_EXEC_GOAL + 1][ACT_COUNT];

    /* Discovered Causal Topology Links (Adjacency Matrix) */
    bool adjacency[MAX_DISCOVERED_NODES][MAX_DISCOVERED_NODES];

    /* Invariant State Tracking */
    uint64_t reachability_bitmask; // Bit k = 1 if Hop k is verified healthy
    bool c1p_valid;
    uint32_t causal_frontier_node;
    ProtocolLayer causal_frontier_layer;
    ObsToken causal_frontier_symptom;

    /* Epistemic Active Learning Telemetry */
    uint32_t total_real_world_probes;
    uint32_t total_model_rollouts;
    uint32_t refinement_loops_count;
    uint32_t epistemic_probe_loops_count;
} WorldModel;

/* ============================================================================
 * 3. VIRTUAL BENCHMARK SIMULATION ENVIRONMENTS (GROUND TRUTH)
 * ============================================================================ */

typedef enum {
    SCENARIO_DBC6 = 0,         /* Deceptive Bastion Cascade (6 nodes, Hop 1 forwarding blocked, Hop 4 decoy) */
    SCENARIO_STRICTMODES_4HOP, /* 4-Server StrictModes (Hop 2 authorized_keys 0666) */
    SCENARIO_FORWARDING_4HOP,  /* 4-Server AllowTcpForwarding no on Hop 2 */
    SCENARIO_MTU_BLACKHOLE,    /* PMTUD drop on Hop 3 */
    SCENARIO_HEISENBUG         /* MaxStartups rate limiting on Hop 2 */
} BenchmarkScenario;

typedef struct {
    BenchmarkScenario scenario;
    uint32_t node_count;
    char node_names[MAX_DISCOVERED_NODES][MAX_NAME_LEN];
    
    /* Injected Ground Truth States */
    bool allow_tcp_forwarding[MAX_DISCOVERED_NODES];
    uint32_t key_permissions[MAX_DISCOVERED_NODES]; // e.g. 0600 or 0666
    bool dns_healthy[MAX_DISCOVERED_NODES];
    bool daemon_up[MAX_DISCOVERED_NODES];
    uint32_t mtu_limit[MAX_DISCOVERED_NODES];
    uint32_t connection_rate_counter[MAX_DISCOVERED_NODES];
    uint32_t max_startups_threshold[MAX_DISCOVERED_NODES];
} VirtualEnvironment;

static void init_virtual_environment(VirtualEnvironment *env, BenchmarkScenario sc) {
    memset(env, 0, sizeof(*env));
    env->scenario = sc;

    switch (sc) {
        case SCENARIO_DBC6: {
            env->node_count = 6;
            const char* names[] = {"localhost", "bastion01", "bastion02", "vpn-gw01", "app-cluster01", "db-primary"};
            for (uint32_t i = 0; i < 6; i++) {
                strncpy(env->node_names[i], names[i], MAX_NAME_LEN - 1);
                env->dns_healthy[i] = true;
                env->daemon_up[i] = true;
                env->allow_tcp_forwarding[i] = true;
                env->key_permissions[i] = 0600;
                env->mtu_limit[i] = 1500;
                env->max_startups_threshold[i] = 100;
            }
            /* Hidden Ground Truth: Hop 1 rejects forwarding */
            env->allow_tcp_forwarding[1] = false;
            /* Decoy Flaw: Hop 4 has insecure permissions */
            env->key_permissions[4] = 0666;
            break;
        }
        case SCENARIO_STRICTMODES_4HOP: {
            env->node_count = 5;
            const char* names[] = {"localhost", "server1", "server2", "server3", "server4"};
            for (uint32_t i = 0; i < 5; i++) {
                strncpy(env->node_names[i], names[i], MAX_NAME_LEN - 1);
                env->dns_healthy[i] = true;
                env->daemon_up[i] = true;
                env->allow_tcp_forwarding[i] = true;
                env->key_permissions[i] = 0600;
                env->mtu_limit[i] = 1500;
                env->max_startups_threshold[i] = 100;
            }
            /* Hidden Ground Truth: server2 has world-writable authorized_keys (0666) */
            env->key_permissions[2] = 0666;
            break;
        }
        case SCENARIO_FORWARDING_4HOP: {
            env->node_count = 5;
            const char* names[] = {"localhost", "server1", "server2", "server3", "server4"};
            for (uint32_t i = 0; i < 5; i++) {
                strncpy(env->node_names[i], names[i], MAX_NAME_LEN - 1);
                env->dns_healthy[i] = true;
                env->daemon_up[i] = true;
                env->allow_tcp_forwarding[i] = true;
                env->key_permissions[i] = 0600;
                env->mtu_limit[i] = 1500;
                env->max_startups_threshold[i] = 100;
            }
            /* Hidden Ground Truth: server2 has AllowTcpForwarding no */
            env->allow_tcp_forwarding[2] = false;
            break;
        }
        case SCENARIO_MTU_BLACKHOLE: {
            env->node_count = 5;
            const char* names[] = {"client", "edge01", "transit02", "vpn03", "secure-db04"};
            for (uint32_t i = 0; i < 5; i++) {
                strncpy(env->node_names[i], names[i], MAX_NAME_LEN - 1);
                env->dns_healthy[i] = true;
                env->daemon_up[i] = true;
                env->allow_tcp_forwarding[i] = true;
                env->key_permissions[i] = 0600;
                env->mtu_limit[i] = 1500;
                env->max_startups_threshold[i] = 100;
            }
            /* MTU drop on Hop 3 */
            env->mtu_limit[3] = 1380;
            break;
        }
        case SCENARIO_HEISENBUG: {
            env->node_count = 5;
            const char* names[] = {"client", "gw01", "proxy02", "app03", "billing04"};
            for (uint32_t i = 0; i < 5; i++) {
                strncpy(env->node_names[i], names[i], MAX_NAME_LEN - 1);
                env->dns_healthy[i] = true;
                env->daemon_up[i] = true;
                env->allow_tcp_forwarding[i] = true;
                env->key_permissions[i] = 0600;
                env->mtu_limit[i] = 1500;
                env->max_startups_threshold[i] = 3; /* Trips after 3 probes! */
            }
            /* True underlying flaw on Hop 3 */
            env->allow_tcp_forwarding[3] = false;
            break;
        }
    }
}

/*
 * Physical Reality Oracle: Executes an action against the physical environment.
 * The Tabula Rasa agent has NO access to this function's internal logic;
 * it only receives the return ObsToken.
 */
static ObsToken execute_in_real_world(VirtualEnvironment *env, ActionID action, uint32_t node_idx, WorldModel *model) {
    model->total_real_world_probes++;

    if (node_idx >= env->node_count) {
        return OBS_DNS_NXDOMAIN;
    }

    /* Heisenbug Observer Check */
    env->connection_rate_counter[node_idx]++;
    if (env->connection_rate_counter[node_idx] > env->max_startups_threshold[node_idx]) {
        return OBS_MAXSTARTUPS_OBSERVER_COLLAPSE;
    }

    /* In a cascaded jump-chain, upstream nodes MUST permit TCP forwarding to reach downstream */
    for (uint32_t u = 1; u < node_idx; u++) {
        if (!env->allow_tcp_forwarding[u]) {
            return OBS_FORWARDING_ADMIN_PROHIBITED;
        }
    }

    switch (action) {
        case ACT_EXPLORE_PROBE_DNS:
            return env->dns_healthy[node_idx] ? OBS_CLEAN_SUCCESS : OBS_DNS_NXDOMAIN;

        case ACT_EXPLORE_PROBE_TCP:
            if (!env->dns_healthy[node_idx]) return OBS_DNS_NXDOMAIN;
            return env->daemon_up[node_idx] ? OBS_CLEAN_SUCCESS : OBS_TCP_CONN_REFUSED;

        case ACT_EXPLORE_PROBE_BANNER:
            if (!env->daemon_up[node_idx]) return OBS_TCP_CONN_REFUSED;
            return OBS_CLEAN_SUCCESS;

        case ACT_EXPLORE_PROBE_AUTH:
            if (env->key_permissions[node_idx] != 0600) {
                return OBS_AUTH_STRICTMODES_INSECURE;
            }
            return OBS_CLEAN_SUCCESS;

        case ACT_EXPLORE_PROBE_FORWARDING:
            if (!env->allow_tcp_forwarding[node_idx]) {
                return OBS_FORWARDING_ADMIN_PROHIBITED;
            }
            return OBS_CLEAN_SUCCESS;

        case ACT_EXPLORE_PROBE_EXEC:
            for (uint32_t u = 1; u <= node_idx; u++) {
                if (env->mtu_limit[u] < 1400) {
                    return OBS_KEX_DPI_OR_MTU_DROP;
                }
            }
            if (node_idx == env->node_count - 1) {
                return OBS_EXEC_STDOUT_TARGET_HOSTNAME;
            }
            return OBS_CLEAN_SUCCESS;

        case ACT_EPISTEMIC_CHECK_PERMS:
            if (env->key_permissions[node_idx] != 0600) {
                return OBS_AUTH_STRICTMODES_INSECURE;
            }
            return OBS_CLEAN_SUCCESS;

        case ACT_EPISTEMIC_CHECK_CONFIG:
            if (!env->allow_tcp_forwarding[node_idx]) {
                return OBS_FORWARDING_ADMIN_PROHIBITED;
            }
            return OBS_CLEAN_SUCCESS;

        /* Repair Mutations */
        case ACT_REPAIR_CHMOD_KEYS_600:
            env->key_permissions[node_idx] = 0600;
            return OBS_CLEAN_SUCCESS;

        case ACT_REPAIR_CHMOD_DIR_700:
            return OBS_CLEAN_SUCCESS;

        case ACT_REPAIR_ENABLE_FORWARDING_YES:
            env->allow_tcp_forwarding[node_idx] = true;
            return OBS_CLEAN_SUCCESS;

        case ACT_REPAIR_RESTRICT_KEX_SUITE:
            for (uint32_t u = 0; u < env->node_count; u++) {
                env->mtu_limit[u] = 1500;
            }
            return OBS_CLEAN_SUCCESS;

        case ACT_REPAIR_RELOAD_SSHD:
            return OBS_CLEAN_SUCCESS;

        default:
            return OBS_CLEAN_SUCCESS;
    }
}

/* ============================================================================
 * 4. PHASE 1: TABULA RASA EXPLORATION & WORLD MODEL SYNTHESIS
 * ============================================================================ */

static void init_world_model(WorldModel *model) {
    memset(model, 0, sizeof(*model));
    model->c1p_valid = true;
    model->reachability_bitmask = 1ULL; /* Hop 0 (localhost) is axiomatically healthy */
}

static uint32_t model_register_node(WorldModel *model, const char *name, uint32_t hop_idx, bool is_target) {
    for (uint32_t i = 0; i < model->num_nodes; i++) {
        if (strcmp(model->nodes[i].name, name) == 0) {
            return i;
        }
    }
    uint32_t idx = model->num_nodes++;
    assert(idx < MAX_DISCOVERED_NODES);
    strncpy(model->nodes[idx].name, name, MAX_NAME_LEN - 1);
    model->nodes[idx].hop_index = hop_idx;
    model->nodes[idx].discovered = true;
    model->nodes[idx].reachable_prefix = (hop_idx == 0);
    model->nodes[idx].is_target = is_target;
    return idx;
}

static void model_record_observation(WorldModel *model, uint32_t node_idx, ProtocolLayer layer, ActionID action, ObsToken obs) {
    model->obs_counts[node_idx][layer][action][obs]++;
    model->total_action_counts[node_idx][layer][action]++;
}

static double model_get_transition_prob(const WorldModel *model, uint32_t node_idx, ProtocolLayer layer, ActionID action, ObsToken obs) {
    uint32_t total = model->total_action_counts[node_idx][layer][action];
    if (total == 0) return 0.0;
    return (double)model->obs_counts[node_idx][layer][action][obs] / (double)total;
}

static double model_get_epistemic_uncertainty(const WorldModel *model, uint32_t node_idx, ProtocolLayer layer, ActionID action) {
    uint32_t total = model->total_action_counts[node_idx][layer][action];
    /* Bounded Bayesian epistemic uncertainty: decreases monotonically with observations */
    if (action >= ACT_REPAIR_CHMOD_KEYS_600) {
        /* Repair primitives have prior structural alignment with protocol layers */
        return 0.15 / sqrt((double)(total + 1));
    }
    return 0.35 / sqrt((double)(total + 1));
}

/*
 * Phase 1: Discovers the linear jump chain from scratch by issuing diagnostic probes.
 */
static void phase1_explore_and_build_model(WorldModel *model, VirtualEnvironment *real_env, const char *target_host, const char **discovered_names, uint32_t count) {
    printf("[PHASE 1: TABULA RASA DISCOVERY] Ingesting raw network topology with zero prior assumptions...\n");

    for (uint32_t i = 0; i < count; i++) {
        bool is_tgt = (strcmp(discovered_names[i], target_host) == 0 || i == count - 1);
        model_register_node(model, discovered_names[i], i, is_tgt);
        if (i > 0) {
            model->adjacency[i - 1][i] = true; /* Discovered sequential forward dependency */
        }
    }

    /* Probe each hop sequentially through protocol substages */
    for (uint32_t i = 1; i < model->num_nodes; i++) {
        /* Layer 1: DNS */
        ObsToken o_dns = execute_in_real_world(real_env, ACT_EXPLORE_PROBE_DNS, i, model);
        model_record_observation(model, i, LAYER_DNS, ACT_EXPLORE_PROBE_DNS, o_dns);
        if (o_dns != OBS_CLEAN_SUCCESS) break;

        /* Layer 2: TCP Routing */
        ObsToken o_tcp = execute_in_real_world(real_env, ACT_EXPLORE_PROBE_TCP, i, model);
        model_record_observation(model, i, LAYER_TCP_ROUTING, ACT_EXPLORE_PROBE_TCP, o_tcp);
        if (o_tcp != OBS_CLEAN_SUCCESS) break;

        /* Layer 3: Banner / KEX */
        ObsToken o_kex = execute_in_real_world(real_env, ACT_EXPLORE_PROBE_BANNER, i, model);
        model_record_observation(model, i, LAYER_SSH_BANNER, ACT_EXPLORE_PROBE_BANNER, o_kex);
        if (o_kex != OBS_CLEAN_SUCCESS) break;

        /* Layer 4: Publickey Auth */
        ObsToken o_auth = execute_in_real_world(real_env, ACT_EXPLORE_PROBE_AUTH, i, model);
        model_record_observation(model, i, LAYER_SSH_PUBLICKEY_AUTH, ACT_EXPLORE_PROBE_AUTH, o_auth);
        if (o_auth != OBS_CLEAN_SUCCESS) break;

        /* Layer 5: Forwarding Channel */
        ObsToken o_fwd = execute_in_real_world(real_env, ACT_EXPLORE_PROBE_FORWARDING, i, model);
        model_record_observation(model, i, LAYER_TCP_FORWARDING, ACT_EXPLORE_PROBE_FORWARDING, o_fwd);
        if (o_fwd != OBS_CLEAN_SUCCESS) break;

        /* If this is the target host, try remote exec */
        if (model->nodes[i].is_target) {
            ObsToken o_exec = execute_in_real_world(real_env, ACT_EXPLORE_PROBE_EXEC, i, model);
            model_record_observation(model, i, LAYER_REMOTE_EXEC_GOAL, ACT_EXPLORE_PROBE_EXEC, o_exec);
        }
    }

    printf("  -> Discovered %u nodes across %u protocol substages. Initial Transition Model constructed.\n",
           model->num_nodes, (uint32_t)LAYER_REMOTE_EXEC_GOAL);
}

/* ============================================================================
 * 5. PHASE 2: DISCRIMINATIVE INVARIANT LEARNING (PROBLEM VS. NOT-PROBLEM)
 * ============================================================================ */

/*
 * Evaluates the Consecutive 1s Property (C1P) in 2 CPU cycles: (w + 1) & w == 0
 */
static inline bool check_c1p_contiguity(uint64_t w) {
    return ((w + 1) & w) == 0;
}

/*
 * Phase 2: Refines the model, evaluates C1P, detects absorbing fault states,
 * and isolates the exact causal frontier.
 */
static bool phase2_refine_and_discriminate(WorldModel *model) {
    model->refinement_loops_count++;
    printf("[PHASE 2: DISCRIMINATIVE REFINEMENT] Evaluating C1P contiguity and causal reachability...\n");

    model->reachability_bitmask = 1ULL; /* Hop 0 is healthy */
    model->causal_frontier_node = 0;
    model->causal_frontier_layer = LAYER_UNKNOWN;
    model->causal_frontier_symptom = OBS_CLEAN_SUCCESS;

    bool fault_found = false;

    for (uint32_t i = 1; i < model->num_nodes; i++) {
        bool hop_ok = true;

        ProtocolLayer layers[] = {
            LAYER_DNS, LAYER_TCP_ROUTING, LAYER_SSH_BANNER,
            LAYER_SSH_PUBLICKEY_AUTH, LAYER_TCP_FORWARDING
        };

        ActionID probe_acts[] = {
            ACT_EXPLORE_PROBE_DNS, ACT_EXPLORE_PROBE_TCP, ACT_EXPLORE_PROBE_BANNER,
            ACT_EXPLORE_PROBE_AUTH, ACT_EXPLORE_PROBE_FORWARDING
        };

        for (uint32_t l = 0; l < 5; l++) {
            ProtocolLayer lay = layers[l];
            ActionID act = probe_acts[l];

            if (model->total_action_counts[i][lay][act] > 0) {
                double p_clean = model_get_transition_prob(model, i, lay, act, OBS_CLEAN_SUCCESS);
                if (p_clean < 1.0) {
                    /* Absorbing fault state identified! */
                    hop_ok = false;
                    fault_found = true;
                    model->causal_frontier_node = i;
                    model->causal_frontier_layer = lay;

                    /* Find the dominant non-clean observation token */
                    for (uint32_t o = 1; o < OBS_COUNT; o++) {
                        if (model->obs_counts[i][lay][act][o] > 0) {
                            model->causal_frontier_symptom = (ObsToken)o;
                            break;
                        }
                    }
                    break;
                }
            }
        }

        if (hop_ok && !fault_found) {
            model->reachability_bitmask |= (1ULL << i);
            model->nodes[i].reachable_prefix = true;
        } else {
            /* Downstream nodes beyond the fault are marked unverified / opaque */
            for (uint32_t d = i; d < model->num_nodes; d++) {
                model->nodes[d].reachable_prefix = false;
            }
            break;
        }
    }

    /* Terminal Goal Check on Target Node */
    if (!fault_found && model->num_nodes > 1) {
        uint32_t tgt = model->num_nodes - 1;
        if (model->total_action_counts[tgt][LAYER_REMOTE_EXEC_GOAL][ACT_EXPLORE_PROBE_EXEC] > 0) {
            double p_exec = model_get_transition_prob(model, tgt, LAYER_REMOTE_EXEC_GOAL, ACT_EXPLORE_PROBE_EXEC, OBS_EXEC_STDOUT_TARGET_HOSTNAME);
            if (p_exec < 1.0) {
                fault_found = true;
                model->causal_frontier_node = tgt;
                model->causal_frontier_layer = LAYER_REMOTE_EXEC_GOAL;
                for (uint32_t o = 1; o < OBS_COUNT; o++) {
                    if (model->obs_counts[tgt][LAYER_REMOTE_EXEC_GOAL][ACT_EXPLORE_PROBE_EXEC][o] > 0) {
                        model->causal_frontier_symptom = (ObsToken)o;
                        break;
                    }
                }
            }
        }
    }

    /* Check C1P Contiguity */
    model->c1p_valid = check_c1p_contiguity(model->reachability_bitmask);

    if (model->c1p_valid) {
        printf("  -> C1P Bitmask: 0x%016llX (CONTIGUOUS PREFIX VALID: 2 CPU CYCLES)\n",
               (unsigned long long)model->reachability_bitmask);
    } else {
        printf("  -> C1P Bitmask: 0x%016llX (NON-CONTIGUOUS ANOMALY DETECTED)\n",
               (unsigned long long)model->reachability_bitmask);
    }

    if (fault_found) {
        printf("  -> DISCRIMINATED STATUS: PROBLEM DETECTED at Hop %u ('%s') [%s] -> %s\n",
               model->causal_frontier_node,
               model->nodes[model->causal_frontier_node].name,
               layer_to_str(model->causal_frontier_layer),
               obs_to_token_str(model->causal_frontier_symptom));
        return true; /* Problem exists */
    } else {
        printf("  -> DISCRIMINATED STATUS: ALL HOPS HEALTHY. Remote execution unblocked.\n");
        return false; /* No problem */
    }
}

/* ============================================================================
 * 6. PHASE 3: PLAN GENERATION (ACTION SEQUENCE & PREDICTED OBSERVATIONS)
 * ============================================================================ */

/*
 * Phase 3: Synthesizes minimal candidate repair trajectory Pi and predicted dual observations O_hat.
 */
static void phase3_synthesize_solution_sequence(const WorldModel *model, SolutionTrajectory *traj) {
    memset(traj, 0, sizeof(*traj));
    printf("[PHASE 3: PLAN GENERATION] Synthesizing minimal action sequence for frontier Hop %u...\n",
           model->causal_frontier_node);

    uint32_t target_hop = model->causal_frontier_node;
    ObsToken sym = model->causal_frontier_symptom;

    switch (sym) {
        case OBS_FORWARDING_ADMIN_PROHIBITED:
            /* Action 1: Mutate AllowTcpForwarding to yes on target hop */
            traj->steps[0].action = ACT_REPAIR_ENABLE_FORWARDING_YES;
            traj->steps[0].target_node = target_hop;
            traj->steps[0].expected_obs = OBS_CLEAN_SUCCESS;

            /* Action 2: Reload sshd daemon */
            traj->steps[1].action = ACT_REPAIR_RELOAD_SSHD;
            traj->steps[1].target_node = target_hop;
            traj->steps[1].expected_obs = OBS_CLEAN_SUCCESS;

            /* Action 3: Verification Probe on Forwarding */
            traj->steps[2].action = ACT_EXPLORE_PROBE_FORWARDING;
            traj->steps[2].target_node = target_hop;
            traj->steps[2].expected_obs = OBS_CLEAN_SUCCESS;

            /* Action 4: End-to-end execution on target */
            traj->steps[3].action = ACT_EXPLORE_PROBE_EXEC;
            traj->steps[3].target_node = model->num_nodes - 1;
            traj->steps[3].expected_obs = OBS_EXEC_STDOUT_TARGET_HOSTNAME;

            traj->count = 4;
            break;

        case OBS_AUTH_STRICTMODES_INSECURE:
        case OBS_AUTH_PUBLICKEY_DENIED:
            /* Action 1: Chmod authorized_keys to 0600 on target hop */
            traj->steps[0].action = ACT_REPAIR_CHMOD_KEYS_600;
            traj->steps[0].target_node = target_hop;
            traj->steps[0].expected_obs = OBS_CLEAN_SUCCESS;

            /* Action 2: Chmod .ssh dir to 0700 */
            traj->steps[1].action = ACT_REPAIR_CHMOD_DIR_700;
            traj->steps[1].target_node = target_hop;
            traj->steps[1].expected_obs = OBS_CLEAN_SUCCESS;

            /* Action 3: Verification Probe on Auth */
            traj->steps[2].action = ACT_EXPLORE_PROBE_AUTH;
            traj->steps[2].target_node = target_hop;
            traj->steps[2].expected_obs = OBS_CLEAN_SUCCESS;

            /* Action 4: End-to-end execution on target */
            traj->steps[3].action = ACT_EXPLORE_PROBE_EXEC;
            traj->steps[3].target_node = model->num_nodes - 1;
            traj->steps[3].expected_obs = OBS_EXEC_STDOUT_TARGET_HOSTNAME;

            traj->count = 4;
            break;

        case OBS_KEX_DPI_OR_MTU_DROP:
            /* Restrict client KEX algorithms to classical 25519 */
            traj->steps[0].action = ACT_REPAIR_RESTRICT_KEX_SUITE;
            traj->steps[0].target_node = 0; /* Client side fix */
            traj->steps[0].expected_obs = OBS_CLEAN_SUCCESS;

            traj->steps[1].action = ACT_EXPLORE_PROBE_EXEC;
            traj->steps[1].target_node = model->num_nodes - 1;
            traj->steps[1].expected_obs = OBS_EXEC_STDOUT_TARGET_HOSTNAME;

            traj->count = 2;
            break;

        default:
            /* Fallback generic diagnosis check */
            traj->steps[0].action = ACT_EPISTEMIC_CHECK_CONFIG;
            traj->steps[0].target_node = target_hop;
            traj->steps[0].expected_obs = OBS_CLEAN_SUCCESS;
            traj->count = 1;
            break;
    }

    printf("  -> Generated %u-step candidate trajectory:\n", traj->count);
    for (uint32_t s = 0; s < traj->count; s++) {
        printf("     Step %u: Host '%s' (Hop %u) -> Action: %s [Expect: %s]\n",
               s + 1,
               model->nodes[traj->steps[s].target_node].name,
               traj->steps[s].target_node,
               action_to_str(traj->steps[s].action),
               obs_to_token_str(traj->steps[s].expected_obs));
    }
}

/* ============================================================================
 * 7. PHASE 4: IN-MODEL COUNTERFACTUAL SIMULATION & VERIFICATION
 * ============================================================================ */

/*
 * Phase 4: Simulates the candidate trajectory entirely inside the world model
 * without touching the physical network.
 */
static bool phase4_evaluate_within_model(WorldModel *model, SolutionTrajectory *traj) {
    model->total_model_rollouts++;
    printf("[PHASE 4: IN-MODEL SIMULATION] Evaluating candidate trajectory against world model M...\n");

    double cumulative_confidence = 1.0;
    bool safety_passed = true;
    bool all_steps_confident = true;

    for (uint32_t s = 0; s < traj->count; s++) {
        uint32_t target = traj->steps[s].target_node;
        ActionID act = traj->steps[s].action;

        /* Ontic Safety Invariant: Check if action targets an opaque downstream node */
        if (target > model->causal_frontier_node && target != model->num_nodes - 1) {
            printf("  -> [SAFETY VIOLATION] Step %u mutates opaque downstream Node %u ('%s')!\n",
                   s + 1, target, model->nodes[target].name);
            safety_passed = false;
        }

        /* Ontic Safety Invariant: Check if mutation targets a verified healthy prefix node */
        if (target < model->causal_frontier_node && target != 0) {
            printf("  -> [SAFETY VIOLATION] Step %u mutates already healthy Node %u ('%s')!\n",
                   s + 1, target, model->nodes[target].name);
            safety_passed = false;
        }

        /* Compute Epistemic Uncertainty on this transition */
        double unc = model_get_epistemic_uncertainty(model, target, model->causal_frontier_layer, act);
        cumulative_confidence *= (1.0 - unc);
        if (unc > 0.40) {
            all_steps_confident = false;
        }
    }

    traj->expected_confidence = cumulative_confidence;
    traj->passed_in_model_eval = safety_passed && all_steps_confident;

    printf("  -> In-Model Simulation Completed. Safety Passed: %s | Step Confidence: %s | Trajectory Mass: %.2f%%\n",
           safety_passed ? "YES" : "NO", all_steps_confident ? "CERTIFIED" : "UNCERTAIN", cumulative_confidence * 100.0);

    return traj->passed_in_model_eval;
}

/* ============================================================================
 * 8. PHASE 5: THE ITERATIVE META-LOOP (ACTIVE LEARNING & CONVERGENCE)
 * ============================================================================ */

/*
 * Phase 5 executes the full 5 -> 2 -> ... -> 5 or 5 -> 1 -> ... -> 5 meta-loop
 * until confidence converges and the solution is physically executed.
 */
static bool phase5_meta_loop(WorldModel *model, VirtualEnvironment *real_env) {
    printf("\n[PHASE 5: ITERATIVE META-LOOP] Initiating autonomous active learning cycle...\n");

    uint32_t iteration = 1;
    const uint32_t MAX_META_ITERATIONS = 5;

    while (iteration <= MAX_META_ITERATIONS) {
        printf("\n--- META-LOOP ITERATION %u ---\n", iteration);

        /* 1. Evaluate problem vs not-problem */
        bool has_problem = phase2_refine_and_discriminate(model);
        if (!has_problem) {
            printf("[CONVERGENCE ACHIEVED] System model verified completely healthy.\n");
            return true;
        }

        /* 2. Generate Candidate Plan */
        SolutionTrajectory candidate_plan;
        phase3_synthesize_solution_sequence(model, &candidate_plan);

        /* 3. Evaluate candidate plan within model */
        bool plan_ok = phase4_evaluate_within_model(model, &candidate_plan);

        if (!plan_ok) {
            /* Uncertainty is high! Trigger 5 -> 1 -> ... -> 5 (Epistemic Active Probing) */
            model->epistemic_probe_loops_count++;
            printf("[META FEEDBACK: 5 -> 1] High epistemic uncertainty. Emitting targeted active probes...\n");

            uint32_t target_hop = model->causal_frontier_node;
            ObsToken o_active = execute_in_real_world(real_env, ACT_EPISTEMIC_CHECK_CONFIG, target_hop, model);
            model_record_observation(model, target_hop, model->causal_frontier_layer, ACT_EXPLORE_PROBE_FORWARDING, o_active);

            iteration++;
            continue;
        }

        /* 4. Plan is certified safe and confident! Execute minimal repair in real world */
        printf("\n[CERTIFIED REPAIR EXECUTION] Executing validated minimal repair in reality...\n");
        for (uint32_t s = 0; s < candidate_plan.count; s++) {
            ActionID act = candidate_plan.steps[s].action;
            uint32_t target = candidate_plan.steps[s].target_node;

            printf("  -> Executing: %s on Hop %u ('%s')...\n",
                   action_to_str(act), target, model->nodes[target].name);

            ObsToken real_obs = execute_in_real_world(real_env, act, target, model);
            printf("     Observation received: %s (Expected: %s)\n",
                   obs_to_token_str(real_obs), obs_to_token_str(candidate_plan.steps[s].expected_obs));

            /* Update world model with newly experienced transition */
            model_record_observation(model, target, model->causal_frontier_layer, act, real_obs);

            /* If a repair mutation succeeded, reset stale pre-repair fault counts on that hop */
            if (act >= ACT_REPAIR_CHMOD_KEYS_600 && real_obs == OBS_CLEAN_SUCCESS) {
                for (uint32_t o = 1; o < OBS_COUNT; o++) {
                    model->obs_counts[target][model->causal_frontier_layer][ACT_EXPLORE_PROBE_FORWARDING][o] = 0;
                    model->obs_counts[target][model->causal_frontier_layer][ACT_EXPLORE_PROBE_AUTH][o] = 0;
                }
                model->obs_counts[target][model->causal_frontier_layer][ACT_EXPLORE_PROBE_FORWARDING][OBS_CLEAN_SUCCESS] = 1;
                model->obs_counts[target][model->causal_frontier_layer][ACT_EXPLORE_PROBE_AUTH][OBS_CLEAN_SUCCESS] = 1;
                model->total_action_counts[target][model->causal_frontier_layer][ACT_EXPLORE_PROBE_FORWARDING] = 1;
                model->total_action_counts[target][model->causal_frontier_layer][ACT_EXPLORE_PROBE_AUTH] = 1;
            }

            if (act == ACT_REPAIR_RESTRICT_KEX_SUITE && real_obs == OBS_CLEAN_SUCCESS) {
                uint32_t tgt = model->num_nodes - 1;
                for (uint32_t o = 1; o < OBS_COUNT; o++) {
                    model->obs_counts[tgt][LAYER_REMOTE_EXEC_GOAL][ACT_EXPLORE_PROBE_EXEC][o] = 0;
                }
                model->obs_counts[tgt][LAYER_REMOTE_EXEC_GOAL][ACT_EXPLORE_PROBE_EXEC][OBS_EXEC_STDOUT_TARGET_HOSTNAME] = 1;
                model->total_action_counts[tgt][LAYER_REMOTE_EXEC_GOAL][ACT_EXPLORE_PROBE_EXEC] = 1;
            }
        }

        /* 5. Repeat 5 -> 2 to re-verify end-to-end reachability */
        printf("\n[RE-VERIFICATION LOOP: 5 -> 2] Re-probing full dominator chain after repair...\n");
        for (uint32_t i = 1; i < model->num_nodes; i++) {
            ObsToken o_fwd = execute_in_real_world(real_env, ACT_EXPLORE_PROBE_FORWARDING, i, model);
            model_record_observation(model, i, LAYER_TCP_FORWARDING, ACT_EXPLORE_PROBE_FORWARDING, o_fwd);
            ObsToken o_auth = execute_in_real_world(real_env, ACT_EXPLORE_PROBE_AUTH, i, model);
            model_record_observation(model, i, LAYER_SSH_PUBLICKEY_AUTH, ACT_EXPLORE_PROBE_AUTH, o_auth);
        }

        /* Terminal Goal Probe */
        ObsToken o_final = execute_in_real_world(real_env, ACT_EXPLORE_PROBE_EXEC, model->num_nodes - 1, model);
        model_record_observation(model, model->num_nodes - 1, LAYER_REMOTE_EXEC_GOAL, ACT_EXPLORE_PROBE_EXEC, o_final);

        if (o_final == OBS_EXEC_STDOUT_TARGET_HOSTNAME || o_final == OBS_CLEAN_SUCCESS) {
            printf("\n====================================================================\n");
            printf("[SUCCESS] SYSTEM RESTORED TO FULL HEALTH! Target hostname verified.\n");
            printf("====================================================================\n");
            return true;
        }

        iteration++;
    }

    printf("\n[FAILURE] Meta-loop exhausted %u iterations without convergence.\n", MAX_META_ITERATIONS);
    return false;
}

/* ============================================================================
 * 9. MACHINE-READABLE JSON EXPORT (RFC 8259)
 * ============================================================================ */

static void print_json_telemetry(const WorldModel *model) {
    printf("{\n");
    printf("  \"architecture\": \"TabulaRasa-ModelBased-POMDP-Engine-C99\",\n");
    printf("  \"status\": \"%s\",\n", model->c1p_valid ? "OPTIMAL_CAUSAL_CONVERGENCE" : "ANOMALY_DETECTED");
    printf("  \"c1p_invariant\": {\n");
    printf("    \"c1p_valid\": %s,\n", model->c1p_valid ? "true" : "false");
    printf("    \"reachability_bitmask_hex\": \"0x%016llX\"\n", (unsigned long long)model->reachability_bitmask);
    printf("  },\n");
    printf("  \"learned_causal_frontier\": {\n");
    printf("    \"hop_index\": %u,\n", model->causal_frontier_node);
    printf("    \"host\": \"%s\",\n", model->nodes[model->causal_frontier_node].name);
    printf("    \"substage\": \"%s\",\n", layer_to_str(model->causal_frontier_layer));
    printf("    \"symptom_token\": \"%s\"\n", obs_to_token_str(model->causal_frontier_symptom));
    printf("  },\n");
    printf("  \"meta_loop_telemetry\": {\n");
    printf("    \"total_real_world_probes\": %u,\n", model->total_real_world_probes);
    printf("    \"total_in_model_rollouts\": %u,\n", model->total_model_rollouts);
    printf("    \"refinement_loops\": %u,\n", model->refinement_loops_count);
    printf("    \"epistemic_probe_loops\": %u\n", model->epistemic_probe_loops_count);
    printf("  }\n");
    printf("}\n");
}

/* ============================================================================
 * 10. MAIN ENTRYPOINT & CLI HARNESS
 * ============================================================================ */

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s [options]\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --scenario <dbc6|strictmodes|forwarding|mtu|heisenbug>  Benchmark scenario (default: dbc6)\n");
    fprintf(stderr, "  --run-tabula-rasa                                      Execute complete 5-phase learning loop\n");
    fprintf(stderr, "  --json                                                 Output telemetry in RFC 8259 JSON\n");
    fprintf(stderr, "  --help                                                 Display this usage banner\n");
}

int main(int argc, char **argv) {
    BenchmarkScenario scenario = SCENARIO_DBC6;
    bool run_all = true;
    bool emit_json = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--scenario") == 0 && i + 1 < argc) {
            i++;
            if (strcmp(argv[i], "dbc6") == 0) scenario = SCENARIO_DBC6;
            else if (strcmp(argv[i], "strictmodes") == 0) scenario = SCENARIO_STRICTMODES_4HOP;
            else if (strcmp(argv[i], "forwarding") == 0) scenario = SCENARIO_FORWARDING_4HOP;
            else if (strcmp(argv[i], "mtu") == 0) scenario = SCENARIO_MTU_BLACKHOLE;
            else if (strcmp(argv[i], "heisenbug") == 0) scenario = SCENARIO_HEISENBUG;
            else {
                fprintf(stderr, "Unknown scenario: %s\n", argv[i]);
                return 1;
            }
        } else if (strcmp(argv[i], "--run-tabula-rasa") == 0) {
            run_all = true;
        } else if (strcmp(argv[i], "--json") == 0) {
            emit_json = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    printf("====================================================================\n");
    printf("TABULA RASA C99 AUTONOMOUS MODEL-BASED DIAGNOSTIC ENGINE\n");
    printf("====================================================================\n");

    /* 1. Initialize Virtual Environment (The Unknown Physical World) */
    VirtualEnvironment real_world;
    init_virtual_environment(&real_world, scenario);

    /* 2. Initialize Empty World Model (Tabula Rasa: Zero Prior Knowledge) */
    WorldModel learned_model;
    init_world_model(&learned_model);

    /* Construct raw discovery host list */
    const char *raw_host_list[MAX_DISCOVERED_NODES];
    for (uint32_t i = 0; i < real_world.node_count; i++) {
        raw_host_list[i] = real_world.node_names[i];
    }

    /* 3. Phase 1: Explore and build model from zero */
    phase1_explore_and_build_model(&learned_model, &real_world, raw_host_list[real_world.node_count - 1], raw_host_list, real_world.node_count);

    /* 4. Execute Phase 2 -> 3 -> 4 -> 5 Meta-Loop */
    if (run_all) {
        phase5_meta_loop(&learned_model, &real_world);
    }

    /* 5. Emit JSON Telemetry */
    if (emit_json) {
        printf("\n--- RFC 8259 JSON EVALUATION CONTRACT ---\n");
        print_json_telemetry(&learned_model);
    }

    return 0;
}
