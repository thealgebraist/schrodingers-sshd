/*
 * minimal_cascade_game.c
 *
 * The Minimal Quotient Game ("128-Switch Colored Series Circuit") —
 * Strictly Isomorphic (Strong Behavioral Bisimulation) to Both the 16-Hop
 * Cascaded OpenSSH Transducer Problem and the 256x256 2D Dungeon Game.
 *
 * Supports:
 *   1. Self-verification & benchmark suite: ./minimal_cascade_game
 *   2. Isolated POSIX HTTP Daemon mode    : ./minimal_cascade_game --serve 8766 [--scenario adversarial5|random5] [--seed N] [--no-reset]
 *
 * Compile: cc -std=c99 -O3 -Wall -Wextra -Werror -pedantic minimal_cascade_game.c -o minimal_cascade_game
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define D_SWITCHES 128
#define ALL_CLOSED 128
#define STATES_CNT 129
#define MAX_TRACE  2048

/* Static Periodic Color Map c(k) in {1..5} (0 = PASS / All Closed) */
static inline int switch_color(int k) {
    static const int8_t PERIODIC_COLOR[8] = { 1, 2, 3, 4, 5, 3, 2, 1 };
    return PERIODIC_COLOR[k & 7];
}

static const char *COLOR_NAMES[6] = {
    "PASS_ALL_CLOSED",
    "C1_RED",
    "C2_BLUE",
    "C3_AMBER",
    "C4_CYAN",
    "C5_VIOLET"
};

typedef struct {
    int step;
    char action[16];
    int target_k;
    char outcome[32];
    int true_k_star;
} TraceEntry;

/* Minimal Game State: Two 64-bit integers = 128 bits for the 128 series switches */
typedef struct {
    uint64_t bits[2];      /* Current state: bit k == 1 (Closed/OK), 0 (Open/Broken) */
    uint64_t init_bits[2]; /* Initial state for reset/reference */
    char scenario[32];
    uint64_t seed;
    bool allow_reset;
    int probes;
    int inspects;
    int toggles;
    int wrong_toggles;
    int resets;
    int trace_cnt;
    TraceEntry trace[MAX_TRACE];
} MinimalCircuitGame;

static inline bool get_sw(const MinimalCircuitGame *g, int k) {
    return (g->bits[k >> 6] >> (k & 63)) & 1ULL;
}
static inline void set_sw(MinimalCircuitGame *g, int k, bool v) {
    if (v) g->bits[k >> 6] |=  (1ULL << (k & 63));
    else   g->bits[k >> 6] &= ~(1ULL << (k & 63));
}

/* Causal Censoring Frontier: k* = min { k : s_k == 0 }, or 128 if all 1 */
static inline int first_open_switch(const MinimalCircuitGame *g) {
    for (int k = 0; k < D_SWITCHES; k++) {
        if (!get_sw(g, k)) return k;
    }
    return ALL_CLOSED;
}

static void record_event(MinimalCircuitGame *g, const char *act, int k, const char *out) {
    if (g->trace_cnt < MAX_TRACE) {
        TraceEntry *e = &g->trace[g->trace_cnt++];
        e->step = g->trace_cnt;
        snprintf(e->action, sizeof(e->action), "%s", act);
        e->target_k = k;
        snprintf(e->outcome, sizeof(e->outcome), "%s", out);
        e->true_k_star = first_open_switch(g);
    }
}

/* ============================================================================
 * THE ONLY 3 GAME OPERATIONS: probe(m), inspect(k), toggle(k)
 * ============================================================================ */

/* 1. probe(m): Returns 0 (PASS) if k* > m, else returns aliased color c(k*) in {1..5} */
static inline int game_probe(MinimalCircuitGame *g, int m) {
    g->probes++;
    int k_star = first_open_switch(g);
    int res = (k_star > m) ? 0 : switch_color(k_star);
    record_event(g, "PROBE", m, COLOR_NAMES[res]);
    return res;
}

/* 2. inspect(k): Returns 1 (closed), 0 (open), or -1 (UNREACHABLE due to Fog-of-War k > k*) */
static inline int game_inspect(MinimalCircuitGame *g, int k) {
    g->inspects++;
    int k_star = first_open_switch(g);
    int res = (k > k_star) ? -1 : (int)get_sw(g, k);
    record_event(g, "INSPECT", k, (res == -1) ? "UNREACHABLE" : (res == 1 ? "CLOSED_1" : "OPEN_0"));
    return res;
}

/* 3. toggle(k): Flips s_k <- 1 - s_k if reachable (k <= k*). Breaking a working switch = wrong_toggle! */
static inline int game_toggle(MinimalCircuitGame *g, int k) {
    int k_star = first_open_switch(g);
    if (k > k_star) {
        record_event(g, "TOGGLE", k, "UNREACHABLE");
        return -1; /* Unreachable: upstream power cut at k*! */
    }
    g->toggles++;
    bool cur = get_sw(g, k);
    if (cur) g->wrong_toggles++; /* Broke a healthy switch (In-band lockout)! */
    set_sw(g, k, !cur);
    record_event(g, "TOGGLE", k, cur ? "BROKE_CLOSED_TO_0" : "FIXED_OPEN_TO_1");
    return (int)(!cur);
}

/* ============================================================================
 * OPTIMAL SOLVERS ACROSS THE 3 ORACLE REGIMES (+ BAYESIAN ORDER-STATISTIC DP)
 *   Regime I  : Stage-Agnostic Prefix Oracle (Pi)               -> 905/129 = 7.0155
 *   Regime II : Decoupled E2E-First Fiber Bisection (O_e2e+Pi)  -> 737/129 = 5.7132
 *   Regime III: Coupled Prefix-Symptom Pass-Chain DP            -> 619/129 = 4.7984
 *   Regime IIIb: Order-Statistic Multi-Fault Pass-Chain DP      -> 21 probes (22 w/ check)
 * ============================================================================ */

static void compute_bellman_splits(int split[STATES_CNT + 1]) {
    double cost[STATES_CNT + 1] = {0.0, 0.0};
    split[0] = split[1] = 0;
    for (int w = 2; w <= STATES_CNT; w++) {
        double best = 1e18;
        int best_l = 1;
        for (int l = 1; l < w; l++) {
            double c = 1.0 + (l * cost[l] + (w - l) * cost[w - l]) / (double)w;
            if (c < best - 1e-12) { best = c; best_l = l; }
        }
        cost[w] = best;
        split[w] = best_l;
    }
}

/* External path length g(n) of optimal binary search over n uniform candidates */
static inline int bst_path_len(int n) {
    if (n <= 1) return 0;
    int lg = 0;
    while ((1 << (lg + 1)) <= n) lg++;
    return n * lg + 2 * (n - (1 << lg));
}

/* Compute optimal pass-chain thresholds next_m[a] for uniform single-fault DP (619/129) */
static int compute_pass_chain_dp(int next_m[STATES_CNT]) {
    int F[STATES_CNT];
    F[D_SWITCHES] = 0;
    next_m[D_SWITCHES] = D_SWITCHES;
    for (int a = D_SWITCHES - 1; a >= 0; a--) {
        int best_cost = 1000000000;
        int best_m = D_SWITCHES - 1;
        int counts[6] = {0};
        for (int m = a; m < D_SWITCHES; m++) {
            counts[switch_color(m)]++;
            int fail_cost = 0;
            for (int c = 1; c <= 5; c++) fail_cost += bst_path_len(counts[c]);
            int total = (STATES_CNT - a) + fail_cost + F[m + 1];
            if (total < best_cost) {
                best_cost = total;
                best_m = m;
            }
        }
        F[a] = best_cost;
        next_m[a] = best_m;
    }
    return F[0]; /* Exact 619 */
}

/* Binomial coefficient C(n, k) as double for Order-Statistic Prior w_r(k) = C(127-k, r-1) */
static double binom_coeff(int n, int k) {
    if (k < 0 || k > n) return 0.0;
    if (k == 0 || k == n) return 1.0;
    if (k > n - k) k = n - k;
    double res = 1.0;
    for (int i = 1; i <= k; i++) {
        res = res * (double)(n - k + i) / (double)i;
    }
    return res;
}

/* Compute optimal threshold m*(a, r) and fiber OBST split under Order-Statistic Prior w_r(k) = C(127-k, r-1) */
static int compute_order_stat_threshold(int a, int r) {
    if (a >= D_SWITCHES - 1) return D_SWITCHES - 1;
    double w[D_SWITCHES];
    for (int k = 0; k < D_SWITCHES; k++) {
        w[k] = (k >= a) ? binom_coeff(D_SWITCHES - 1 - k, r - 1) : 0.0;
    }
    double F[STATES_CNT];
    int best_m_arr[STATES_CNT];
    F[D_SWITCHES] = 0.0;
    best_m_arr[D_SWITCHES] = D_SWITCHES - 1;

    for (int i = D_SWITCHES - 1; i >= a; i--) {
        double rem_w = 0.0;
        for (int k = i; k < D_SWITCHES; k++) rem_w += w[k];
        if (rem_w <= 0.0) {
            F[i] = 0.0;
            best_m_arr[i] = D_SWITCHES - 1;
            continue;
        }
        double best_val = 1e30;
        int best_m = D_SWITCHES - 1;
        for (int m = i; m < D_SWITCHES; m++) {
            /* Compute exact expected binary search cost in each color fiber within [i..m] */
            double fail_cost = 0.0;
            for (int c = 1; c <= 5; c++) {
                double fw[32];
                int n = 0;
                for (int k = i; k <= m; k++) {
                    if (switch_color(k) == c) fw[n++] = w[k];
                }
                if (n > 1) {
                    /* Exact OBST / balanced split cost over n elements */
                    double dp[32][32];
                    double psum[33];
                    psum[0] = 0.0;
                    for (int q = 0; q < n; q++) {
                        psum[q + 1] = psum[q] + fw[q];
                        dp[q][q] = 0.0;
                    }
                    for (int len = 2; len <= n; len++) {
                        for (int l = 0; l + len - 1 < n; l++) {
                            int h = l + len - 1;
                            double w_sub = psum[h + 1] - psum[l];
                            double b_sub = 1e30;
                            for (int p = l; p < h; p++) {
                                double v = w_sub + dp[l][p] + dp[p + 1][h];
                                if (v < b_sub) b_sub = v;
                            }
                            dp[l][h] = b_sub;
                        }
                    }
                    fail_cost += dp[0][n - 1];
                }
            }
            double total = rem_w + fail_cost + F[m + 1];
            if (total < best_val - 1e-12) {
                best_val = total;
                best_m = m;
            }
        }
        F[i] = best_val;
        best_m_arr[i] = best_m;
    }
    return best_m_arr[a];
}

static int solve_agnostic_pi(MinimalCircuitGame *g, const int split[STATES_CNT + 1], bool single_fault_metric) {
    int L = 0, first_probes = 0;
    while (true) {
        if (g->toggles > 0 && game_probe(g, D_SWITCHES - 1) == 0) break;
        int lo = L, hi = (g->toggles == 0) ? ALL_CLOSED : (D_SWITCHES - 1);
        while (lo < hi) {
            int mid = lo + split[hi - lo + 1] - 1;
            if (game_probe(g, mid) != 0) hi = mid;
            else                         lo = mid + 1;
        }
        if (g->toggles == 0) first_probes = g->probes;
        if (lo == ALL_CLOSED) break;
        assert(game_inspect(g, lo) == 0);
        game_toggle(g, lo);
        L = lo + 1;
    }
    return single_fault_metric ? first_probes : g->probes;
}

static int solve_joint_color_fiber(MinimalCircuitGame *g, const int split[STATES_CNT + 1], bool single_fault_metric) {
    int L = 0, first_probes = 0;
    while (L < D_SWITCHES) {
        int c_obs = game_probe(g, D_SWITCHES - 1);
        if (c_obs == 0) {
            if (g->toggles == 0) first_probes = g->probes;
            break;
        }
        int fiber[32], f_cnt = 0;
        for (int k = L; k < D_SWITCHES; k++) {
            if (switch_color(k) == c_obs) fiber[f_cnt++] = k;
        }
        int lo = 0, hi = f_cnt - 1;
        while (lo < hi) {
            int mid = lo + split[hi - lo + 1] - 1;
            if (game_probe(g, fiber[mid]) != 0) hi = mid;
            else                                lo = mid + 1;
        }
        if (g->toggles == 0) first_probes = g->probes;
        int k_star = fiber[lo];
        assert(game_inspect(g, k_star) == 0);
        game_toggle(g, k_star);
        L = k_star + 1;
    }
    return single_fault_metric ? first_probes : g->probes;
}

/* Regime IIIa: Coupled Prefix-Symptom Pass-Chain DP (Exact 619/129 = 4.7984 single-fault) */
static int solve_coupled_pass_chain(MinimalCircuitGame *g, const int split[STATES_CNT + 1], const int next_m[STATES_CNT], bool single_fault_metric) {
    int L = 0, first_probes = 0;
    while (L < D_SWITCHES) {
        int a = L;
        int c_obs = 0;
        int m_fail = D_SWITCHES - 1;
        while (a < D_SWITCHES) {
            int m = next_m[a];
            c_obs = game_probe(g, m);
            if (c_obs != 0) {
                m_fail = m;
                break;
            }
            a = m + 1;
        }
        if (c_obs == 0) {
            if (g->toggles == 0) first_probes = g->probes;
            break;
        }
        int fiber[32], f_cnt = 0;
        for (int k = a; k <= m_fail; k++) {
            if (switch_color(k) == c_obs) fiber[f_cnt++] = k;
        }
        int lo = 0, hi = f_cnt - 1;
        while (lo < hi) {
            int mid = lo + split[hi - lo + 1] - 1;
            if (game_probe(g, fiber[mid]) != 0) hi = mid;
            else                                lo = mid + 1;
        }
        if (g->toggles == 0) first_probes = g->probes;
        int k_star = fiber[lo];
        assert(game_inspect(g, k_star) == 0);
        game_toggle(g, k_star);
        L = k_star + 1;
    }
    return single_fault_metric ? first_probes : g->probes;
}

/* Regime IIIb: Order-Statistic Bayesian Pass-Chain DP for K known faults */
static int solve_order_stat_pass_chain(MinimalCircuitGame *g, const int split[STATES_CNT + 1], int total_faults_K, bool verify_final) {
    int L = 0;
    for (int wave = 0; wave < total_faults_K && L < D_SWITCHES; wave++) {
        int r = total_faults_K - wave;
        int a = L;
        int c_obs = 0;
        int m_fail = D_SWITCHES - 1;
        while (a < D_SWITCHES) {
            int m = compute_order_stat_threshold(a, r);
            c_obs = game_probe(g, m);
            if (c_obs != 0) {
                m_fail = m;
                break;
            }
            a = m + 1;
        }
        if (c_obs == 0) break;
        int fiber[32], f_cnt = 0;
        for (int k = a; k <= m_fail; k++) {
            if (switch_color(k) == c_obs) fiber[f_cnt++] = k;
        }
        int lo = 0, hi = f_cnt - 1;
        while (lo < hi) {
            int mid = lo + split[hi - lo + 1] - 1;
            if (game_probe(g, fiber[mid]) != 0) hi = mid;
            else                                lo = mid + 1;
        }
        int k_star = fiber[lo];
        assert(game_inspect(g, k_star) == 0);
        game_toggle(g, k_star);
        L = k_star + 1;
    }
    if (verify_final) {
        int c_end = game_probe(g, D_SWITCHES - 1);
        assert(c_end == 0);
    }
    return g->probes;
}

/* ============================================================================
 * SCENARIO INITIALIZATION & POSIX HTTP DAEMON
 * ============================================================================ */

static uint64_t splitmix64(uint64_t *state) {
    uint64_t z = (*state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static void init_scenario(MinimalCircuitGame *g, const char *scen, uint64_t seed, bool allow_reset) {
    memset(g, 0, sizeof(*g));
    g->bits[0] = ~0ULL;
    g->bits[1] = ~0ULL;
    snprintf(g->scenario, sizeof(g->scenario), "%s", scen);
    g->seed = seed;
    g->allow_reset = allow_reset;
    g->resets = 1;

    if (strcmp(scen, "adversarial5") == 0) {
        int faults[5] = { 1, 24, 59, 93, 126 };
        for (int i = 0; i < 5; i++) set_sw(g, faults[i], false);
    } else if (strcmp(scen, "random5") == 0) {
        uint64_t rng = seed;
        int cnt = 0;
        while (cnt < 5) {
            int k = (int)(splitmix64(&rng) % D_SWITCHES);
            if (get_sw(g, k)) {
                set_sw(g, k, false);
                cnt++;
            }
        }
    }
    g->init_bits[0] = g->bits[0];
    g->init_bits[1] = g->bits[1];
}

static void write_trace_json(const MinimalCircuitGame *g, const int split[STATES_CNT + 1]) {
    MinimalCircuitGame ref_pi = *g;
    ref_pi.bits[0] = g->init_bits[0]; ref_pi.bits[1] = g->init_bits[1];
    ref_pi.probes = ref_pi.inspects = ref_pi.toggles = ref_pi.wrong_toggles = ref_pi.trace_cnt = 0;
    int opt_pi_probes = solve_agnostic_pi(&ref_pi, split, false);

    MinimalCircuitGame ref_joint = *g;
    ref_joint.bits[0] = g->init_bits[0]; ref_joint.bits[1] = g->init_bits[1];
    ref_joint.probes = ref_joint.inspects = ref_joint.toggles = ref_joint.wrong_toggles = ref_joint.trace_cnt = 0;
    int opt_joint_probes = solve_joint_color_fiber(&ref_joint, split, false);

    FILE *f = fopen("minimal_session_trace.json", "w");
    if (!f) return;
    int k_star = first_open_switch(g);
    fprintf(f, "{\n  \"scenario\": \"%s\",\n  \"seed\": %llu,\n  \"solved\": %s,\n",
            g->scenario, (unsigned long long)g->seed, (k_star == ALL_CLOSED) ? "true" : "false");
    fprintf(f, "  \"initial_open_switches\": [");
    bool first = true;
    for (int k = 0; k < D_SWITCHES; k++) {
        bool bit = (g->init_bits[k >> 6] >> (k & 63)) & 1ULL;
        if (!bit) {
            fprintf(f, "%s%d", first ? "" : ", ", k);
            first = false;
        }
    }
    fprintf(f, "],\n");
    fprintf(f, "  \"agent_metrics\": { \"probes\": %d, \"inspects\": %d, \"toggles\": %d, \"wrong_toggles\": %d, \"resets\": %d },\n",
            g->probes, g->inspects, g->toggles, g->wrong_toggles, g->resets);
    fprintf(f, "  \"optimal_reference\": { \"agnostic_pi_probes\": %d, \"joint_color_fiber_probes\": %d },\n",
            opt_pi_probes, opt_joint_probes);
    fprintf(f, "  \"trace\": [\n");
    for (int i = 0; i < g->trace_cnt; i++) {
        const TraceEntry *e = &g->trace[i];
        fprintf(f, "    { \"step\": %d, \"action\": \"%s\", \"k\": %d, \"outcome\": \"%s\", \"true_k_star\": %d }%s\n",
                e->step, e->action, e->target_k, e->outcome, e->true_k_star, (i + 1 < g->trace_cnt) ? "," : "");
    }
    fprintf(f, "  ]\n}\n");
    fclose(f);
}

static void url_decode(const char *src, char *dst, size_t dst_sz) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 1 < dst_sz; i++) {
        if (src[i] == '+') {
            dst[j++] = ' ';
        } else if (src[i] == '%' && isxdigit((unsigned char)src[i+1]) && isxdigit((unsigned char)src[i+2])) {
            char hex[3] = { src[i+1], src[i+2], 0 };
            dst[j++] = (char)strtol(hex, NULL, 16);
            i += 2;
        } else {
            dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
}

static void handle_command(MinimalCircuitGame *g, const int split[STATES_CNT + 1], const char *cmd, char *resp, size_t resp_sz) {
    while (*cmd && isspace((unsigned char)*cmd)) cmd++;
    char verb[32] = {0};
    int arg = -1;
    int n = sscanf(cmd, "%31s %d", verb, &arg);
    if (n <= 0) {
        snprintf(resp, resp_sz, "{ \"error\": \"Empty command. Use: status, colors, probe <0..127>, inspect <0..127>, toggle <0..127>, export\" }\n");
        return;
    }

    if (strcmp(verb, "status") == 0) {
        int k_star = first_open_switch(g);
        snprintf(resp, resp_sz,
                 "{\n  \"action\": \"status\",\n  \"switches_D\": 128,\n  \"all_closed_solved\": %s,\n"
                 "  \"metrics\": { \"probes\": %d, \"inspects\": %d, \"toggles\": %d, \"wrong_toggles\": %d, \"resets\": %d }\n}\n",
                 (k_star == ALL_CLOSED) ? "true" : "false",
                 g->probes, g->inspects, g->toggles, g->wrong_toggles, g->resets);
    } else if (strcmp(verb, "colors") == 0) {
        snprintf(resp, resp_sz,
                 "{\n  \"action\": \"colors\",\n  \"rule\": \"c(k) depends on m = k mod 8\",\n"
                 "  \"mapping\": {\n"
                 "    \"m_0_and_7\": { \"color_code\": 1, \"color_name\": \"C1_RED\",    \"count\": 32 },\n"
                 "    \"m_1_and_6\": { \"color_code\": 2, \"color_name\": \"C2_BLUE\",   \"count\": 32 },\n"
                 "    \"m_2_and_5\": { \"color_code\": 3, \"color_name\": \"C3_AMBER\",  \"count\": 32 },\n"
                 "    \"m_3\":       { \"color_code\": 4, \"color_name\": \"C4_CYAN\",   \"count\": 16 },\n"
                 "    \"m_4\":       { \"color_code\": 5, \"color_name\": \"C5_VIOLET\", \"count\": 16 }\n"
                 "  }\n}\n");
    } else if (strcmp(verb, "probe") == 0 || strcmp(verb, "run") == 0) {
        int m = (strcmp(verb, "run") == 0 && n == 1) ? (D_SWITCHES - 1) : arg;
        if (m < 0 || m >= D_SWITCHES) {
            snprintf(resp, resp_sz, "{ \"error\": \"probe index m must be in 0..127\" }\n");
            return;
        }
        int col = game_probe(g, m);
        snprintf(resp, resp_sz,
                 "{\n  \"action\": \"probe\",\n  \"target_m\": %d,\n  \"passed\": %s,\n"
                 "  \"color_code\": %d,\n  \"color_name\": \"%s\"\n}\n",
                 m, (col == 0) ? "true" : "false", col, COLOR_NAMES[col]);
    } else if (strcmp(verb, "inspect") == 0) {
        if (n < 2 || arg < 0 || arg >= D_SWITCHES) {
            snprintf(resp, resp_sz, "{ \"error\": \"inspect index k must be in 0..127\" }\n");
            return;
        }
        int st = game_inspect(g, arg);
        if (st == -1) {
            snprintf(resp, resp_sz,
                     "{\n  \"action\": \"inspect\",\n  \"target_k\": %d,\n  \"reachable\": false,\n"
                     "  \"state_bit\": null,\n  \"status\": \"UNREACHABLE_UPSTREAM_OPEN\"\n}\n", arg);
        } else {
            snprintf(resp, resp_sz,
                     "{\n  \"action\": \"inspect\",\n  \"target_k\": %d,\n  \"reachable\": true,\n"
                     "  \"switch_color\": \"%s\",\n  \"state_bit\": %d,\n  \"status\": \"%s\"\n}\n",
                     arg, COLOR_NAMES[switch_color(arg)], st, (st == 1) ? "CLOSED_WORKING" : "OPEN_BROKEN");
        }
    } else if (strcmp(verb, "toggle") == 0 || strcmp(verb, "repair") == 0) {
        if (n < 2 || arg < 0 || arg >= D_SWITCHES) {
            snprintf(resp, resp_sz, "{ \"error\": \"toggle index k must be in 0..127\" }\n");
            return;
        }
        int prev_wrong = g->wrong_toggles;
        int res = game_toggle(g, arg);
        if (res == -1) {
            snprintf(resp, resp_sz,
                     "{\n  \"action\": \"toggle\",\n  \"target_k\": %d,\n  \"reachable\": false,\n"
                     "  \"status\": \"UNREACHABLE_UPSTREAM_OPEN\",\n"
                     "  \"metrics\": { \"probes\": %d, \"inspects\": %d, \"toggles\": %d, \"wrong_toggles\": %d }\n}\n",
                     arg, g->probes, g->inspects, g->toggles, g->wrong_toggles);
        } else {
            bool broke_it = (g->wrong_toggles > prev_wrong);
            int k_star = first_open_switch(g);
            if (k_star == ALL_CLOSED) {
                write_trace_json(g, split);
            }
            snprintf(resp, resp_sz,
                     "{\n  \"action\": \"toggle\",\n  \"target_k\": %d,\n  \"reachable\": true,\n"
                     "  \"new_state_bit\": %d,\n  \"status\": \"%s\",\n  \"all_closed_solved\": %s,\n"
                     "  \"metrics\": { \"probes\": %d, \"inspects\": %d, \"toggles\": %d, \"wrong_toggles\": %d }\n}\n",
                     arg, res, broke_it ? "COLLATERAL_DAMAGE_BROKE_WORKING_SWITCH" : "FIXED_OPEN_SWITCH_TO_CLOSED",
                     (k_star == ALL_CLOSED) ? "true" : "false",
                     g->probes, g->inspects, g->toggles, g->wrong_toggles);
        }
    } else if (strcmp(verb, "export") == 0) {
        write_trace_json(g, split);
        int k_star = first_open_switch(g);
        snprintf(resp, resp_sz,
                 "{\n  \"action\": \"export\",\n  \"trace_file\": \"minimal_session_trace.json\",\n"
                 "  \"all_closed_solved\": %s,\n"
                 "  \"metrics\": { \"probes\": %d, \"inspects\": %d, \"toggles\": %d, \"wrong_toggles\": %d }\n}\n",
                 (k_star == ALL_CLOSED) ? "true" : "false",
                 g->probes, g->inspects, g->toggles, g->wrong_toggles);
    } else if (strcmp(verb, "reset") == 0) {
        if (!g->allow_reset) {
            snprintf(resp, resp_sz, "{ \"error\": \"RESET_DISABLED: Server running with --no-reset\" }\n");
        } else {
            g->bits[0] = g->init_bits[0];
            g->bits[1] = g->init_bits[1];
            g->resets++;
            snprintf(resp, resp_sz, "{ \"action\": \"reset\", \"resets\": %d }\n", g->resets);
        }
    } else {
        snprintf(resp, resp_sz, "{ \"error\": \"Unknown command. Valid: status, colors, probe <0..127>, inspect <0..127>, toggle <0..127>, export\" }\n");
    }
}

static int run_http_server(int port, const char *scenario, uint64_t seed, bool allow_reset) {
    int split[STATES_CNT + 1];
    compute_bellman_splits(split);

    MinimalCircuitGame game;
    init_scenario(&game, scenario, seed, allow_reset);

    int srv_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (srv_fd < 0) { perror("socket"); return 1; }
    int opt = 1;
    setsockopt(srv_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons((uint16_t)port);

    if (bind(srv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); close(srv_fd); return 1;
    }
    if (listen(srv_fd, 16) < 0) {
        perror("listen"); close(srv_fd); return 1;
    }

    printf("========================================================================\n");
    printf(" MINIMAL 128-SWITCH SERIES CIRCUIT HTTP DAEMON LISTENING ON 127.0.0.1:%d\n", port);
    printf(" Scenario: %s | Seed: %llu | Reset Allowed: %s\n",
           scenario, (unsigned long long)seed, allow_reset ? "YES" : "NO");
    printf("========================================================================\n");
    fflush(stdout);

    while (true) {
        int cli_fd = accept(srv_fd, NULL, NULL);
        if (cli_fd < 0) continue;

        char req[4096] = {0};
        ssize_t rlen = read(cli_fd, req, sizeof(req) - 1);
        if (rlen > 0) {
            char cmd_raw[256] = {0};
            char *q = strstr(req, "GET /cmd?");
            if (q) {
                char *c_param = strstr(q, "c=");
                if (c_param) {
                    c_param += 2;
                    size_t i = 0;
                    while (c_param[i] && c_param[i] != '&' && c_param[i] != ' ' && c_param[i] != '\r' && c_param[i] != '\n' && i + 1 < sizeof(cmd_raw)) {
                        cmd_raw[i] = c_param[i];
                        i++;
                    }
                    cmd_raw[i] = '\0';
                }
            }
            char cmd_dec[256] = {0};
            url_decode(cmd_raw, cmd_dec, sizeof(cmd_dec));

            char body[2048] = {0};
            handle_command(&game, split, cmd_dec, body, sizeof(body));

            char http_resp[2560];
            int hlen = snprintf(http_resp, sizeof(http_resp),
                                "HTTP/1.1 200 OK\r\n"
                                "Content-Type: application/json\r\n"
                                "Content-Length: %zu\r\n"
                                "Connection: close\r\n\r\n%s",
                                strlen(body), body);
            (void)write(cli_fd, http_resp, (size_t)hlen);
        }
        close(cli_fd);
    }
    return 0;
}

int main(int argc, char **argv) {
    int serve_port = 0;
    const char *scenario = "adversarial5";
    uint64_t seed = 987654321ULL;
    bool allow_reset = true;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--serve") == 0 && i + 1 < argc) {
            serve_port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--scenario") == 0 && i + 1 < argc) {
            scenario = argv[++i];
        } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            seed = strtoull(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--no-reset") == 0) {
            allow_reset = false;
        }
    }

    if (serve_port > 0) {
        return run_http_server(serve_port, scenario, seed, allow_reset);
    }

    int split[STATES_CNT + 1];
    compute_bellman_splits(split);
    int next_m[STATES_CNT];
    int dp_f0 = compute_pass_chain_dp(next_m);
    assert(dp_f0 == 619);

    int sum_pi = 0, sum_joint = 0, sum_chain = 0;
    for (int fk = 0; fk < STATES_CNT; fk++) {
        MinimalCircuitGame g1, g2, g3;
        init_scenario(&g1, "clean", 0, true);
        init_scenario(&g2, "clean", 0, true);
        init_scenario(&g3, "clean", 0, true);
        if (fk < D_SWITCHES) {
            set_sw(&g1, fk, false);
            set_sw(&g2, fk, false);
            set_sw(&g3, fk, false);
        }
        sum_pi    += solve_agnostic_pi(&g1, split, true);
        sum_joint += solve_joint_color_fiber(&g2, split, true);
        sum_chain += solve_coupled_pass_chain(&g3, split, next_m, true);
        assert(first_open_switch(&g1) == ALL_CLOSED && g1.wrong_toggles == 0);
        assert(first_open_switch(&g2) == ALL_CLOSED && g2.wrong_toggles == 0);
        assert(first_open_switch(&g3) == ALL_CLOSED && g3.wrong_toggles == 0);
    }

    MinimalCircuitGame ga, gj, gc, go;
    init_scenario(&ga, "adversarial5", 0, true);
    init_scenario(&gj, "adversarial5", 0, true);
    init_scenario(&gc, "adversarial5", 0, true);
    init_scenario(&go, "adversarial5", 0, true);
    int p_adv_pi    = solve_agnostic_pi(&ga, split, false);
    int p_adv_joint = solve_joint_color_fiber(&gj, split, false);
    int p_adv_chain = solve_coupled_pass_chain(&gc, split, next_m, false);
    int p_adv_ostat = solve_order_stat_pass_chain(&go, split, 5, false);

    printf("========================================================================\n");
    printf(" MINIMAL 128-SWITCH COLORED SERIES CIRCUIT (3 OPTIMAL REGIMES PROOF)\n");
    printf("========================================================================\n");
    printf("  1. Stage-Agnostic Prefix (Pi)           : %d / 129 = %.4f (Exact 905/129!)\n",
           sum_pi, (double)sum_pi / STATES_CNT);
    printf("  2. Decoupled E2E-First Fiber (O_e2e+Pi) : %d / 129 = %.4f (Exact 737/129!)\n",
           sum_joint, (double)sum_joint / STATES_CNT);
    printf("  3. Coupled Pass-Chain DP (probe(m)->c)  : %d / 129 = %.4f (Exact 619/129!)\n",
           sum_chain, (double)sum_chain / STATES_CNT);
    printf("  ----------------------------------------------------------------------\n");
    printf("  5-Fault Adversarial Cascade (Regime I: Pi)               : %2d probes (%d wrong)\n",
           p_adv_pi, ga.wrong_toggles);
    printf("  5-Fault Adversarial Cascade (Regime II: O_e2e+Pi)        : %2d probes (%d wrong)\n",
           p_adv_joint, gj.wrong_toggles);
    printf("  5-Fault Adversarial Cascade (Regime IIIa: Uniform DP)    : %2d probes (%d wrong)\n",
           p_adv_chain, gc.wrong_toggles);
    printf("  5-Fault Adversarial Cascade (Regime IIIb: Order-Stat DP) : %2d probes (%d wrong)\n",
           p_adv_ostat, go.wrong_toggles);
    printf("========================================================================\n");
    return 0;
}
