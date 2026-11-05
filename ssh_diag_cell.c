/*
 * ssh_diag_cell.c - Minimal Guarded Atomic Action SSH Diagnoser & Solver
 *
 * Implements a bounded Bluespec/Kami-style Guarded Atomic Action (GAA)
 * cell for diagnosing and remediating hidden-state SSH failures,
 * with strict causal priority scheduling for critical system faults
 * (e.g. ENOSPC / 100% full /tmp) over secondary service configuration faults.
 *
 * Standard: C99
 * Memory footprint: 19 bits of register state per server (zero dynamic allocations).
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#define N_SERVERS 4

/* --- 1. HYPOTHESIS BITMASKS (8-BIT REGISTER) --- */
#define H_OK              0x00
#define H_AGENT_OVERFLOW  0x01  /* > MaxAuthTries keys in agent */
#define H_KEY_PASSPHRASE  0x02  /* Private key locked / bad passphrase */
#define H_PUBKEY_DISABLED 0x04  /* PubkeyAuthentication no */
#define H_ALGO_MISMATCH   0x08  /* Deprecated or unshared signature algo */
#define H_STRICT_MODES    0x10  /* ~/.ssh or authorized_keys permission loose */
#define H_KEY_ABSENT      0x20  /* Key not present in authorized_keys */
#define H_PAM_ACCOUNT     0x40  /* Account locked / PAM faillock / nologin */
#define H_SYSTEM_ENOSPC   0x80  /* CRITICAL: /tmp or root partition 100% full (ENOSPC) */
#define H_ALL             0xFF

/* --- 2. PHASE & ACTION REGISTERS --- */
typedef enum {
    PHASE_IDLE = 0,
    PHASE_PROBE_SYSTEM,
    PHASE_PROBE_LOCAL,
    PHASE_PROBE_NONE,
    PHASE_PROBE_ISOLATED,
    PHASE_PROBE_PK_QUERY,
    PHASE_SOLVE_CRITICAL,   /* Tier 1: System Invariants (Disk, I/O) */
    PHASE_SOLVE_CONFIG,     /* Tier 2: SSH Service & Permissions */
    PHASE_DONE
} Phase;

typedef enum {
    ACT_NONE = 0,
    ACT_CHECK_SYSTEM_STORAGE,
    ACT_CHECK_KEY_LOCAL,
    ACT_SEND_NONE_AUTH,
    ACT_SEND_ISOLATED_QUERY,
    ACT_SEND_PK_QUERY,
    ACT_PURGE_TEMP_STORAGE, /* Critical Fix: Free /tmp headroom */
    ACT_APPLY_SSH_FIX,       /* Config Fix: chmod, sshd_config */
    ACT_NOTIFY_SUCCESS
} Action;

typedef enum {
    OBS_WAITING = 0,
    OBS_STORAGE_OK,
    OBS_STORAGE_ENOSPC,     /* 100% full /tmp */
    OBS_KEY_PASS_OK,
    OBS_KEY_PASS_FAIL,
    OBS_NONE_HAS_PUBKEY,
    OBS_NONE_NO_PUBKEY,
    OBS_DISCONNECT_AUTHFAIL,
    OBS_PK_QUERY_OK,        /* Server responded SSH_MSG_USERAUTH_PK_OK */
    OBS_PK_QUERY_FAIL,
    OBS_STORAGE_RESTORED,
    OBS_CONFIG_RESTORED
} Observation;

/* --- 3. BOUNDED STATE REGISTERS (KAMI CELL ANALOGUE) --- */
typedef struct {
    uint8_t     belief;       /* Bitmask of remaining hypotheses */
    Phase       phase;        /* Current execution phase */
    Action      action;       /* Action emitted to environment */
    Observation obs;          /* Input observation received */
    uint8_t     active_fault; /* Current fault being remediated */
} DiagCell;

/* Guarded Atomic Rule: Probe System Storage First */
static inline bool rule_probe_system_guard(const DiagCell *c) {
    return (c->phase == PHASE_PROBE_SYSTEM && c->obs == OBS_WAITING);
}
static inline void rule_probe_system_fire(DiagCell *c) {
    c->action = ACT_CHECK_SYSTEM_STORAGE;
}

/* Guarded Atomic Rule: Evaluate Storage Obs */
static inline bool rule_eval_system_guard(const DiagCell *c) {
    return (c->phase == PHASE_PROBE_SYSTEM && c->obs != OBS_WAITING);
}
static inline void rule_eval_system_fire(DiagCell *c) {
    if (c->obs == OBS_STORAGE_ENOSPC) {
        c->belief |= H_SYSTEM_ENOSPC;
    } else {
        c->belief &= ~H_SYSTEM_ENOSPC;
    }
    c->phase  = PHASE_PROBE_LOCAL;
    c->obs    = OBS_WAITING;
    c->action = ACT_NONE;
}

/* Guarded Atomic Rule: Local Key Check */
static inline bool rule_probe_local_guard(const DiagCell *c) {
    return (c->phase == PHASE_PROBE_LOCAL && c->obs == OBS_WAITING);
}
static inline void rule_probe_local_fire(DiagCell *c) {
    c->action = ACT_CHECK_KEY_LOCAL;
}

/* Guarded Atomic Rule: Evaluate Local Key Obs */
static inline bool rule_eval_local_guard(const DiagCell *c) {
    return (c->phase == PHASE_PROBE_LOCAL && c->obs != OBS_WAITING);
}
static inline void rule_eval_local_fire(DiagCell *c) {
    if (c->obs == OBS_KEY_PASS_FAIL) {
        c->belief |= H_KEY_PASSPHRASE;
    } else {
        c->belief &= ~H_KEY_PASSPHRASE;
    }
    c->phase   = PHASE_PROBE_PK_QUERY;
    c->obs     = OBS_WAITING;
    c->action  = ACT_NONE;
}

/* Guarded Atomic Rule: Probe PK Query */
static inline bool rule_probe_pk_guard(const DiagCell *c) {
    return (c->phase == PHASE_PROBE_PK_QUERY && c->obs == OBS_WAITING);
}
static inline void rule_probe_pk_fire(DiagCell *c) {
    c->action = ACT_SEND_PK_QUERY;
}

/* Guarded Atomic Rule: Evaluate PK Query Obs */
static inline bool rule_eval_pk_guard(const DiagCell *c) {
    return (c->phase == PHASE_PROBE_PK_QUERY && c->obs != OBS_WAITING);
}
static inline void rule_eval_pk_fire(DiagCell *c) {
    if (c->obs == OBS_PK_QUERY_OK) {
        c->belief &= ~H_STRICT_MODES;
    } else {
        c->belief |= H_STRICT_MODES;
    }
    /* Enter solve phase: priority scheduler resolves system before config */
    c->phase  = (c->belief & H_SYSTEM_ENOSPC) ? PHASE_SOLVE_CRITICAL : PHASE_SOLVE_CONFIG;
    c->obs    = OBS_WAITING;
    c->action = ACT_NONE;
}

/* --- CAUSAL PRIORITY SCHEDULER --- */
/* Tier 1 Rule: Critical ENOSPC Storage Emergency MUST fire first */
static inline bool rule_solve_critical_guard(const DiagCell *c) {
    return (c->phase == PHASE_SOLVE_CRITICAL && (c->belief & H_SYSTEM_ENOSPC) && c->obs == OBS_WAITING);
}
static inline void rule_solve_critical_fire(DiagCell *c) {
    c->active_fault = H_SYSTEM_ENOSPC;
    c->action       = ACT_PURGE_TEMP_STORAGE;
}

/* Tier 1 Complete: Clear ENOSPC flag and transition to Tier 2 Config */
static inline bool rule_eval_critical_guard(const DiagCell *c) {
    return (c->phase == PHASE_SOLVE_CRITICAL && c->obs == OBS_STORAGE_RESTORED);
}
static inline void rule_eval_critical_fire(DiagCell *c) {
    c->belief &= ~H_SYSTEM_ENOSPC;
    c->phase   = PHASE_SOLVE_CONFIG;
    c->obs     = OBS_WAITING;
    c->action  = ACT_NONE;
}

/* Tier 2 Rule: SSH Config/Permission Repair (StrictModes) ONLY fires when storage is healthy */
static inline bool rule_solve_config_guard(const DiagCell *c) {
    return (c->phase == PHASE_SOLVE_CONFIG && 
           !(c->belief & H_SYSTEM_ENOSPC) && /* HARD GUARD: Invariant satisfied */
           (c->belief & H_STRICT_MODES) &&
           c->obs == OBS_WAITING);
}
static inline void rule_solve_config_fire(DiagCell *c) {
    c->active_fault = H_STRICT_MODES;
    c->action       = ACT_APPLY_SSH_FIX;
}

/* Tier 2 Complete */
static inline bool rule_eval_config_guard(const DiagCell *c) {
    return (c->phase == PHASE_SOLVE_CONFIG && c->obs == OBS_CONFIG_RESTORED);
}
static inline void rule_eval_config_fire(DiagCell *c) {
    c->belief &= ~H_STRICT_MODES;
    c->phase   = PHASE_DONE;
    c->obs     = OBS_WAITING;
    c->action  = ACT_NOTIFY_SUCCESS;
}

/* Single Step Dispatcher */
void cell_step(DiagCell *c) {
    if      (rule_probe_system_guard(c))  rule_probe_system_fire(c);
    else if (rule_eval_system_guard(c))   rule_eval_system_fire(c);
    else if (rule_probe_local_guard(c))   rule_probe_local_fire(c);
    else if (rule_eval_local_guard(c))    rule_eval_local_fire(c);
    else if (rule_probe_pk_guard(c))      rule_probe_pk_fire(c);
    else if (rule_eval_pk_guard(c))       rule_eval_pk_fire(c);
    else if (rule_solve_critical_guard(c))rule_solve_critical_fire(c);
    else if (rule_eval_critical_guard(c)) rule_eval_critical_fire(c);
    else if (rule_solve_config_guard(c))  rule_solve_config_fire(c);
    else if (rule_eval_config_guard(c))   rule_eval_config_fire(c);
}

int main(void) {
    DiagCell cell = {
        .belief       = H_OK,
        .phase        = PHASE_PROBE_SYSTEM,
        .action       = ACT_NONE,
        .obs          = OBS_WAITING,
        .active_fault = H_OK,
    };

    printf("========================================================================\n");
    printf(" C99 GUARDED ATOMIC ACTION CORE: DUAL-FAULT CAUSAL PRIORITY SCHEDULER\n");
    printf("========================================================================\n");
    printf("Simulating co-existing faults: ENOSPC /tmp (0x80) + StrictModes 0666 (0x10)\n\n");

    for (int step = 0; step < 12; step++) {
        cell_step(&cell);

        if (cell.action == ACT_CHECK_SYSTEM_STORAGE) {
            printf("[Step %02d] Probing system storage -> Observed 100%% FULL /tmp (ENOSPC)\n", step);
            cell.obs = OBS_STORAGE_ENOSPC;
        } else if (cell.action == ACT_CHECK_KEY_LOCAL) {
            printf("[Step %02d] Probing local private key -> Key valid & decrypted\n", step);
            cell.obs = OBS_KEY_PASS_OK;
        } else if (cell.action == ACT_SEND_PK_QUERY) {
            printf("[Step %02d] Probing server publickey query -> Rejected (StrictModes)\n", step);
            cell.obs = OBS_PK_QUERY_FAIL;
        } else if (cell.action == ACT_PURGE_TEMP_STORAGE) {
            printf(">>> [ACTION 1 - PRIORITY ORDER 1] Executing ACT_PURGE_TEMP_STORAGE (Freed /tmp)\n");
            cell.obs = OBS_STORAGE_RESTORED;
        } else if (cell.action == ACT_APPLY_SSH_FIX) {
            printf(">>> [ACTION 2 - PRIORITY ORDER 2] Executing ACT_APPLY_SSH_FIX (chmod 0600 authorized_keys)\n");
            cell.obs = OBS_CONFIG_RESTORED;
        } else if (cell.action == ACT_NOTIFY_SUCCESS) {
            printf("[Step %02d] All preconditions verified. Target authenticated successfully!\n", step);
            break;
        }
    }
    return 0;
}
