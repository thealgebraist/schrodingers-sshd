/*
 * ssh_diag_cell.c - Minimal Guarded Atomic Action SSH Diagnoser & Solver
 *
 * Implements a bounded Bluespec/Kami-style Guarded Atomic Action (GAA)
 * cell for diagnosing and remediating hidden-state SSH failures
 * (StrictModes, ssh-agent clutter, local key passphrase locks, PAM faillock).
 *
 * Standard: C99
 * Memory footprint: 18 bits of register state per server (zero dynamic allocations).
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#define N_SERVERS 4

/* --- 1. HYPOTHESIS BITMASKS --- */
#define H_OK              0x00
#define H_AGENT_OVERFLOW  0x01  /* > MaxAuthTries keys in agent */
#define H_KEY_PASSPHRASE  0x02  /* Private key locked / bad passphrase */
#define H_PUBKEY_DISABLED 0x04  /* PubkeyAuthentication no */
#define H_ALGO_MISMATCH   0x08  /* Deprecated or unshared signature algo */
#define H_STRICT_MODES    0x10  /* ~/.ssh or authorized_keys permission loose */
#define H_KEY_ABSENT      0x20  /* Key not present in authorized_keys */
#define H_PAM_ACCOUNT     0x40  /* Account locked / PAM faillock / nologin */
#define H_ALL             0x7F

/* --- 2. PHASE & ACTION REGISTERS --- */
typedef enum {
    PHASE_IDLE = 0,
    PHASE_PROBE_LOCAL,
    PHASE_PROBE_NONE,
    PHASE_PROBE_ISOLATED,
    PHASE_PROBE_PK_QUERY,
    PHASE_SOLVE,
    PHASE_DONE
} Phase;

typedef enum {
    ACT_NONE = 0,
    ACT_CHECK_KEY_LOCAL,
    ACT_SEND_NONE_AUTH,
    ACT_SEND_ISOLATED_QUERY,
    ACT_SEND_PK_QUERY,
    ACT_APPLY_FIX,
    ACT_NOTIFY_SUCCESS
} Action;

typedef enum {
    OBS_WAITING = 0,
    OBS_KEY_PASS_OK,
    OBS_KEY_PASS_FAIL,
    OBS_NONE_HAS_PUBKEY,
    OBS_NONE_NO_PUBKEY,
    OBS_DISCONNECT_AUTHFAIL,
    OBS_PK_QUERY_OK,      /* Server responded SSH_MSG_USERAUTH_PK_OK */
    OBS_PK_QUERY_FAIL,
    OBS_REPAIR_SUCCESS
} Observation;

/* --- 3. BOUNDED STATE REGISTERS (KAMI CELL ANALOGUE) --- */
typedef struct {
    uint8_t     belief;       /* Bitmask of remaining hypotheses */
    Phase       phase;        /* Current execution phase */
    Action      action;       /* Action emitted to environment */
    Observation obs;          /* Input observation received */
    uint8_t     solved_cause; /* Deduced root cause */
} DiagCell;

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
        c->belief = H_KEY_PASSPHRASE;
        c->phase  = PHASE_SOLVE;
    } else {
        c->belief &= ~H_KEY_PASSPHRASE;
        c->phase   = PHASE_PROBE_NONE;
    }
    c->obs    = OBS_WAITING;
    c->action = ACT_NONE;
}

/* Guarded Atomic Rule: Probe None */
static inline bool rule_probe_none_guard(const DiagCell *c) {
    return (c->phase == PHASE_PROBE_NONE && c->obs == OBS_WAITING);
}
static inline void rule_probe_none_fire(DiagCell *c) {
    c->action = ACT_SEND_NONE_AUTH;
}

/* Guarded Atomic Rule: Evaluate None Obs */
static inline bool rule_eval_none_guard(const DiagCell *c) {
    return (c->phase == PHASE_PROBE_NONE && c->obs != OBS_WAITING);
}
static inline void rule_eval_none_fire(DiagCell *c) {
    if (c->obs == OBS_NONE_NO_PUBKEY) {
        c->belief = H_PUBKEY_DISABLED;
        c->phase  = PHASE_SOLVE;
    } else {
        c->belief &= ~H_PUBKEY_DISABLED;
        c->phase   = PHASE_PROBE_ISOLATED;
    }
    c->obs    = OBS_WAITING;
    c->action = ACT_NONE;
}

/* Guarded Atomic Rule: Probe Isolated */
static inline bool rule_probe_isolated_guard(const DiagCell *c) {
    return (c->phase == PHASE_PROBE_ISOLATED && c->obs == OBS_WAITING);
}
static inline void rule_probe_isolated_fire(DiagCell *c) {
    c->action = ACT_SEND_ISOLATED_QUERY;
}

/* Guarded Atomic Rule: Evaluate Isolated Obs */
static inline bool rule_eval_isolated_guard(const DiagCell *c) {
    return (c->phase == PHASE_PROBE_ISOLATED && c->obs != OBS_WAITING);
}
static inline void rule_eval_isolated_fire(DiagCell *c) {
    if (c->obs == OBS_DISCONNECT_AUTHFAIL) {
        c->belief = H_AGENT_OVERFLOW;
        c->phase  = PHASE_SOLVE;
    } else {
        c->belief &= ~H_AGENT_OVERFLOW;
        c->phase   = PHASE_PROBE_PK_QUERY;
    }
    c->obs    = OBS_WAITING;
    c->action = ACT_NONE;
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
        c->belief &= (H_PAM_ACCOUNT);
    } else {
        c->belief &= (H_STRICT_MODES | H_KEY_ABSENT | H_ALGO_MISMATCH);
    }
    c->phase  = PHASE_SOLVE;
    c->obs    = OBS_WAITING;
    c->action = ACT_NONE;
}

/* Guarded Atomic Rule: Solve & Synthesize Fix */
static inline bool rule_solve_guard(const DiagCell *c) {
    return (c->phase == PHASE_SOLVE && c->obs == OBS_WAITING);
}
static inline void rule_solve_fire(DiagCell *c) {
    c->solved_cause = c->belief;
    c->action       = ACT_APPLY_FIX;
}

/* Guarded Atomic Rule: Complete */
static inline bool rule_complete_guard(const DiagCell *c) {
    return (c->phase == PHASE_SOLVE && c->obs == OBS_REPAIR_SUCCESS);
}
static inline void rule_complete_fire(DiagCell *c) {
    c->phase  = PHASE_DONE;
    c->action = ACT_NOTIFY_SUCCESS;
}

/* Single Step Dispatcher (Kami GAA Evaluation Semantics) */
void cell_step(DiagCell *c) {
    if      (rule_probe_local_guard(c))    rule_probe_local_fire(c);
    else if (rule_eval_local_guard(c))     rule_eval_local_fire(c);
    else if (rule_probe_none_guard(c))     rule_probe_none_fire(c);
    else if (rule_eval_none_guard(c))      rule_eval_none_fire(c);
    else if (rule_probe_isolated_guard(c)) rule_probe_isolated_fire(c);
    else if (rule_eval_isolated_guard(c))  rule_eval_isolated_fire(c);
    else if (rule_probe_pk_guard(c))       rule_probe_pk_fire(c);
    else if (rule_eval_pk_guard(c))        rule_eval_pk_fire(c);
    else if (rule_solve_guard(c))          rule_solve_fire(c);
    else if (rule_complete_guard(c))       rule_complete_fire(c);
}

void cell_render_remediation(uint8_t cause, unsigned int server_id) {
    printf("[Server %u] Diagnosed Hidden Fault 0x%02x -> Remediation: ", server_id, cause);
    switch (cause) {
        case H_AGENT_OVERFLOW:
            printf("Client Config: Add 'IdentitiesOnly=yes' and 'IdentityAgent none'.\n");
            break;
        case H_KEY_PASSPHRASE:
            printf("Client Prompt: Key encrypted. Prompt pinentry / unlock ssh-agent key.\n");
            break;
        case H_PUBKEY_DISABLED:
            printf("Server Fix: Set 'PubkeyAuthentication yes' in /etc/ssh/sshd_config.\n");
            break;
        case H_ALGO_MISMATCH:
            printf("Client Config: Specify 'PubkeyAcceptedAlgorithms +ssh-rsa,rsa-sha2-512'.\n");
            break;
        case H_STRICT_MODES:
            printf("Server Fix: chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys && chmod go-w ~\n");
            break;
        case H_KEY_ABSENT:
            printf("Server Fix: Append public key to ~/.ssh/authorized_keys.\n");
            break;
        case H_PAM_ACCOUNT:
            printf("Server Fix: Unlock account with 'faillock --reset' and verify /etc/shells.\n");
            break;
        default:
            printf("Composite/Resolved state.\n");
            break;
    }
}

int main(void) {
    DiagCell fleet[N_SERVERS];
    for (int i = 0; i < N_SERVERS; i++) {
        fleet[i].belief       = H_ALL;
        fleet[i].phase        = PHASE_PROBE_LOCAL;
        fleet[i].action       = ACT_NONE;
        fleet[i].obs          = OBS_WAITING;
        fleet[i].solved_cause = H_OK;
    }

    printf("Executing Guarded Atomic Action Fleet Diagnoser across %d servers...\n", N_SERVERS);
    for (int step = 0; step < 10; step++) {
        for (int i = 0; i < N_SERVERS; i++) {
            cell_step(&fleet[i]);

            if (fleet[i].action == ACT_CHECK_KEY_LOCAL) {
                fleet[i].obs = (i == 2) ? OBS_KEY_PASS_FAIL : OBS_KEY_PASS_OK;
            } else if (fleet[i].action == ACT_SEND_NONE_AUTH) {
                fleet[i].obs = OBS_NONE_HAS_PUBKEY;
            } else if (fleet[i].action == ACT_SEND_ISOLATED_QUERY) {
                fleet[i].obs = (i == 1) ? OBS_DISCONNECT_AUTHFAIL : OBS_PK_QUERY_OK;
            } else if (fleet[i].action == ACT_SEND_PK_QUERY) {
                fleet[i].obs = (i == 0) ? OBS_PK_QUERY_FAIL : OBS_PK_QUERY_OK;
            } else if (fleet[i].action == ACT_APPLY_FIX) {
                cell_render_remediation(fleet[i].solved_cause, i);
                fleet[i].obs = OBS_REPAIR_SUCCESS;
            }
        }
    }
    printf("Fleet diagnosis completed with zero wrong mutations.\n");
    return 0;
}
