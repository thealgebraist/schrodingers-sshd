// cascaded_dungeon_cli.cpp
//
// C++23 Interactive & Stateful Text-Mode Adventure CLI ("Cyber-Vault 256")
// Formally Isomorphic (Strongly Bisimilar via Phi_iso) to the 16-Hop Cascaded
// SSH Transducer Diagnosis & Repair Problem (N=16 Sectors, M=8 Sub-stages, D=128).
//
// Real-Life SSH Fidelity Features:
//   1. Realistic Fog-of-War (`--no-oracle` / default in `--strict`):
//      Just like real OpenSSH (`ssh -o BatchMode=yes`), the tool does NOT compute
//      or print a "knowledge bracket [lo..hi]" for the agent, nor does `repair`
//      announce whether downstream hops are clear!
//   2. Mixed-Mode `ProxyJump` Trap (`probe-mixed <target>`):
//      Isomorphic to running `ssh -o BatchMode=yes <hop_i>` WITHOUT ensuring
//      upstream ProxyJump subprocesses share a deterministic non-interactive key state.
//      If local passphrase safe S0:1 (k=1) is locked, `probe-mixed` to any downstream
//      sector S_i (i >= 1) returns a FALSE POSITIVE failure at S_i:6 ("KeyRejected at S_i")!
//   3. Blind Mutation Collateral Damage (`--strict`):
//      Calling `repair` on any healthy gadget breaks it (toggles 1 -> 0), modeling
//      a blind config edit on a healthy bastion (`sshd_config` / `authorized_keys`).
//   4. End-of-Session JSON Interaction Trace & Side-by-Side Vector SVG Map:
//      Records every agent action and compares the trajectory against the exact
//      Bellman-Optimal prefix bisection reference solution.
//
// Compile:
//   clang++ -std=c++23 -O3 -Wall -Wextra -Werror -pedantic cascaded_dungeon_cli.cpp -o cascaded_dungeon_cli

#include <algorithm>
#include <array>
#include <cassert>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace cyber_vault {

// ============================================================================
// 1. CONSTANTS & TOPOLOGY OF THE 256x256 BOARD
// ============================================================================

inline constexpr int kGridDim        = 256;
inline constexpr int kSectorGrid     = 4;   // 4x4 Boustrophedon macro-grid
inline constexpr int kSectorSize     = 64;  // Each sector is 64x64 tiles
inline constexpr int kNumSectors     = 16;  // Isomorphic to N=16 SSH Hops
inline constexpr int kGadgetsPerSec  = 8;   // Isomorphic to M=8 Sub-stages per Hop
inline constexpr int kTotalGadgets   = kNumSectors * kGadgetsPerSec; // D = 128
inline constexpr int kAllCleared     = kTotalGadgets;                // 128
inline constexpr int kHypothesisCnt  = kTotalGadgets + 1;            // 129

enum class TileGlyph : char {
    VoidWall      = '#', // Reinforced Concrete Wall
    Floor         = '.', // Walkable Corridor / Room Floor
    KeyVaultDoor  = 'V', // m=0: Key-Vault Door (SSH_AUTH_SOCK)
    KeySafe       = 'K', // m=1: Keypad Safe holding Key_i (Key Passphrase / BatchMode)
    GenBeaconA    = 'G', // m=2: Beacon Generator A (UDP/53 Forward DNS)
    DrawbridgeB   = 'B', // m=3: Chasm Drawbridge (TCP/22 Handshake & 1420 MTU)
    LaserGateL    = 'L', // m=4: Biometric Laser Scanner (SSHv2 KEX / HostKey)
    GenRelayB     = 'R', // m=5: Relay Generator B (Remote sshd UseDNS PTR)
    MainBlastDoor = 'D', // m=6: Main Blast Door requiring Key_i + Gen B (authorized_keys)
    ExitAirlockT  = 'T', // m=7: Sector Exit Airlock to Sector i+1 (AllowTcpForwarding -W)
    ScadaCoreX    = 'X'  // Final Target Objective in Sector 15
};

enum class ObsSymptom : int {
    Victory                  = 0, // Reached SCADA Core in Sector 15
    AccessDeniedOrLocked     = 1, // O_1: Aliases m=0 (Vault Door), m=7 (Airlock)
    KeyOrAuthRejected        = 2, // O_2: Aliases m=1 (Safe Passcode), m=6 (Main Blast Door)
    PowerOrBeaconStallTimeout= 3, // O_3: Aliases m=2 (Gen A), m=5 (Gen B)
    DrawbridgeSeveredReset   = 4, // O_4: Aliases m=3 (Chasm Drawbridge)
    LaserBiometricAlarm      = 5  // O_5: Aliases m=4 (Laser Scanner)
};

struct Coord2D {
    uint8_t x{0};
    uint8_t y{0};
    constexpr bool operator==(const Coord2D&) const = default;
};

struct GadgetSpec {
    int              global_k;
    int              sector_i;
    int              sub_m;
    Coord2D          pos;
    Coord2D          room_min;
    Coord2D          room_max;
    TileGlyph        glyph;
    std::string_view code_tag;
    std::string_view game_name;
    std::string_view ssh_equivalent;
    std::string_view room_description;
    std::string_view inspect_healthy_msg;
    std::string_view inspect_faulty_msg;
    ObsSymptom       aliased_symptom;
};

inline constexpr std::array<std::string_view, kNumSectors> kSectorHostnames = {
    "gw-corp-vpn",      "bst-wan-edge01",   "bst-core-rtr01",   "bst-dmz-fw01",
    "bst-eu-west01",    "bst-de-fra01",     "bst-ot-perim01",   "bst-ot-l35-fw",
    "bst-ot-l3-core",   "bst-scada-agg01",  "bst-hist-db01",    "bst-hmi-jump01",
    "bst-cell-zone01",  "bst-cell-sw02",    "bst-plc-rack04",   "scada-plc-unit04"
};

inline constexpr std::array<std::array<uint8_t, 2>, kGadgetsPerSec> kLocalOffsets = {{
    {10, 20}, // m=0: Vault Door V_i (North Key-Vault entrance)
    {10, 12}, // m=1: Keypad Safe K_i (Inside North Key-Vault Room)
    {22, 48}, // m=2: Beacon Generator A (South Power Room A)
    {28, 32}, // m=3: Chasm Drawbridge B_i (Central Corridor)
    {36, 32}, // m=4: Biometric Laser Gate L_i (Central Corridor)
    {44, 48}, // m=5: Relay Generator B (South Power Room B)
    {50, 32}, // m=6: Main Blast Door D_i (Central Corridor)
    {58, 32}  // m=7: Sector Exit Airlock T_i (East Sector Boundary)
}};

inline constexpr std::array<TileGlyph, kGadgetsPerSec> kSubGlyphs = {
    TileGlyph::KeyVaultDoor,  TileGlyph::KeySafe,       TileGlyph::GenBeaconA,
    TileGlyph::DrawbridgeB,   TileGlyph::LaserGateL,    TileGlyph::GenRelayB,
    TileGlyph::MainBlastDoor, TileGlyph::ExitAirlockT
};

inline constexpr std::array<std::string_view, kGadgetsPerSec> kSubCodeTags = {
    "V", "K", "G", "B", "L", "R", "D", "T"
};

inline constexpr std::array<std::string_view, kGadgetsPerSec> kSubGameNames = {
    "Key-Vault Entrance Door",
    "Encrypted Keypad Safe (Holds Sector Key)",
    "Beacon Power Generator A (Corridor Navigation)",
    "Motorized Chasm Drawbridge (1420mm Clearance)",
    "Biometric Laser Identity Gate",
    "Relay Power Generator B (Blast Door Interlock)",
    "Main Armored Blast Door (Requires Key + Gen B)",
    "Inter-Sector Transit Airlock"
};

inline constexpr std::array<std::string_view, kGadgetsPerSec> kSubSshNames = {
    "Local SSH_AUTH_SOCK Agent IPC Socket",
    "Private Key Decryption in ssh-agent (BatchMode=yes)",
    "Forward DNS (UDP/53 A/AAAA) Resolution",
    "TCP/22 Handshake & 1420-Byte WireGuard MTU",
    "SSHv2 KEX & HostKey Fingerprint Verification",
    "Remote sshd UseDNS=yes Reverse PTR Lookup",
    "Remote ~/.ssh/authorized_keys & StrictModes",
    "Remote sshd AllowTcpForwarding=yes (-W channel)"
};

inline constexpr std::array<ObsSymptom, kGadgetsPerSec> kSubSymptoms = {
    ObsSymptom::AccessDeniedOrLocked,      // m=0
    ObsSymptom::KeyOrAuthRejected,         // m=1
    ObsSymptom::PowerOrBeaconStallTimeout, // m=2
    ObsSymptom::DrawbridgeSeveredReset,    // m=3
    ObsSymptom::LaserBiometricAlarm,       // m=4
    ObsSymptom::PowerOrBeaconStallTimeout, // m=5
    ObsSymptom::KeyOrAuthRejected,         // m=6
    ObsSymptom::AccessDeniedOrLocked       // m=7
};

constexpr Coord2D sector_origin(int sector_i) noexcept {
    int row = sector_i / kSectorGrid;
    int col = (row % 2 == 0) ? (sector_i % kSectorGrid)
                             : (kSectorGrid - 1 - (sector_i % kSectorGrid));
    return Coord2D{
        static_cast<uint8_t>(col * kSectorSize),
        static_cast<uint8_t>(row * kSectorSize)
    };
}

constexpr std::string_view symptom_code_str(ObsSymptom s) noexcept {
    switch (s) {
        case ObsSymptom::Victory:                   return "O_0_SCADA_CORE_REACHED";
        case ObsSymptom::AccessDeniedOrLocked:      return "O_1_INTERLOCK_OR_CONDUIT_SEALED";
        case ObsSymptom::KeyOrAuthRejected:         return "O_2_CREDENTIAL_KEY_REJECTED";
        case ObsSymptom::PowerOrBeaconStallTimeout: return "O_3_GENERATOR_POWER_TIMEOUT_HANG";
        case ObsSymptom::DrawbridgeSeveredReset:    return "O_4_DRAWBRIDGE_CHASM_ABORT";
        case ObsSymptom::LaserBiometricAlarm:       return "O_5_BIOMETRIC_LASER_TRIPPED";
    }
    return "O_UNKNOWN";
}

constexpr std::string_view symptom_human_banner(ObsSymptom s) noexcept {
    switch (s) {
        case ObsSymptom::Victory:
            return "MISSION ACCOMPLISHED: Avatar reached the SCADA Core ('X') in Sector 15!";
        case ObsSymptom::AccessDeniedOrLocked:
            return "ALARM [O_1]: Transit aborted — channel/interlock sealed or socket unreachable. "
                   "[ssh: channel open failed: administratively prohibited / agent socket error]";
        case ObsSymptom::KeyOrAuthRejected:
            return "ALARM [O_2]: Permission denied (publickey). Security lock rejected keycard or safe passcode missing!";
        case ObsSymptom::PowerOrBeaconStallTimeout:
            return "ALARM [O_3]: Operation timed out — Avatar stalled in unpowered dark corridor or relay lookup hang!";
        case ObsSymptom::DrawbridgeSeveredReset:
            return "ALARM [O_4]: Connection reset / MTU frame drop — Chasm drawbridge retracted or jammed mid-crossing!";
        case ObsSymptom::LaserBiometricAlarm:
            return "ALARM [O_5]: Host key / KEX verification failed — Biometric laser grid triggered signature mismatch!";
    }
    return "Unknown telemetry.";
}

inline std::string json_escape(std::string_view sv) {
    std::ostringstream oss;
    for (char c : sv) {
        switch (c) {
            case '"':  oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\n': oss << "\\n";  break;
            case '\r': oss << "\\r";  break;
            case '\t': oss << "\\t";  break;
            default:   oss << c;      break;
        }
    }
    return oss.str();
}

// ============================================================================
// 2. INTERACTION TRACE RECORD & PERSISTENT GAME STATE
// ============================================================================

struct TraceEvent {
    int         step_idx{0};
    std::string action_type{};  // "RUN_E2E", "PROBE", "PROBE_MIXED", "INSPECT", "REPAIR"
    int         target_k{-1};   // -1 for RUN_E2E, 0..127 for targeted actions
    Coord2D     from_pos{4, 32};
    Coord2D     to_pos{4, 32};
    std::string outcome_code{}; // "PASS_1", "BLOCKED_0", "SURGICAL_REPAIR_SUCCESS", etc.
    int         bracket_lo{0};
    int         bracket_hi{128};
    int         true_frontier_k{0};
};

struct OptimalStep {
    int         step_idx{0};
    int         wave_idx{1};
    std::string action_type{}; // "OPT_PROBE", "OPT_REPAIR"
    int         target_k{0};
    Coord2D     from_pos{4, 32};
    Coord2D     to_pos{4, 32};
    std::string outcome_code{};
    int         bracket_lo{0};
    int         bracket_hi{128};
    double      shannon_bits{0.0};
};

struct OptimalSolutionPlan {
    std::vector<int>         initial_fault_ks{};
    std::vector<OptimalStep> steps{};
    int                      total_probes{0};
    int                      total_repairs{0};
};

struct GameState {
    uint32_t                        seed{20261025};
    std::string                     scenario_name{"adversarial5"};
    std::array<bool, kTotalGadgets> gadget_healthy{};
    std::array<bool, kTotalGadgets> initial_faults{};
    Coord2D                         avatar_pos{4, 32};
    int                             avatar_max_reached_k{-1};
    uint16_t                        keys_held_mask{0};
    int                             e2e_runs{0};
    int                             drone_probes{0};
    int                             repairs_attempted{0};
    int                             healthy_gadgets_broken{0};
    int                             collateral_induced{0};
    int                             session_resets{0};
    int                             verified_prefix_lo{0};
    int                             verified_prefix_hi{kTotalGadgets};
    bool                            strict_mode{false};
    bool                            oracle_hints{false}; // If false (default in strict), hides [lo..hi] bracket!
    std::vector<TraceEvent>         trace_events{};
};

class CyberVaultEngine {
public:
    CyberVaultEngine() {
        build_world_geometry();
        compute_bellman_table();
        load_scenario("adversarial5", 20261025, false, false);
    }

    void load_scenario(std::string_view preset, uint32_t seed, bool strict_collateral, bool show_oracle_hints) {
        int prev_resets = state_.session_resets;
        state_ = GameState{};
        state_.seed = seed;
        state_.scenario_name = std::string(preset);
        state_.strict_mode = strict_collateral;
        state_.oracle_hints = show_oracle_hints;
        state_.session_resets = prev_resets;
        state_.gadget_healthy.fill(true);
        state_.initial_faults.fill(false);
        state_.avatar_pos = Coord2D{4, 32};
        state_.verified_prefix_lo = 0;
        state_.verified_prefix_hi = kTotalGadgets;

        if (preset == "simple1") {
            inject_fault(59); // Sector 7, m=3 Drawbridge / MTU
        } else if (preset == "aliasing_trap") {
            inject_fault(1);   // Sector 0, m=1 Key Safe / Passphrase
            inject_fault(126); // Sector 15, m=6 Blast Door / authorized_keys
        } else if (preset == "adversarial5") {
            for (int k : {1, 24, 59, 93, 126}) {
                inject_fault(k);
            }
        } else if (preset == "random1") {
            std::mt19937 rng(seed);
            std::uniform_int_distribution<int> dist(0, kTotalGadgets - 1);
            inject_fault(dist(rng));
        } else if (preset == "random5") {
            std::mt19937 rng(seed);
            std::vector<int> indices(kTotalGadgets);
            for (int i = 0; i < kTotalGadgets; ++i) indices[i] = i;
            std::shuffle(indices.begin(), indices.end(), rng);
            for (int i = 0; i < 5; ++i) inject_fault(indices[i]);
        } else {
            state_.scenario_name = "adversarial5";
            for (int k : {1, 24, 59, 93, 126}) {
                inject_fault(k);
            }
        }
        recompute_avatar_progress();
    }

    void increment_resets() {
        state_.session_resets++;
    }

    bool save_to_file(const std::string& path) const {
        std::ofstream out(path);
        if (!out) return false;
        out << "CYBER_VAULT_256_STATE_V3\n";
        out << state_.seed << " " << state_.scenario_name << " "
            << (state_.strict_mode ? 1 : 0) << " "
            << (state_.oracle_hints ? 1 : 0) << " "
            << state_.session_resets << "\n";
        out << static_cast<int>(state_.avatar_pos.x) << " " << static_cast<int>(state_.avatar_pos.y) << " "
            << state_.avatar_max_reached_k << " " << state_.keys_held_mask << "\n";
        out << state_.e2e_runs << " " << state_.drone_probes << " " << state_.repairs_attempted << " "
            << state_.healthy_gadgets_broken << " " << state_.collateral_induced << " "
            << state_.verified_prefix_lo << " " << state_.verified_prefix_hi << "\n";
        for (int k = 0; k < kTotalGadgets; ++k) {
            out << (state_.gadget_healthy[k] ? '1' : '0');
        }
        out << "\n";
        for (int k = 0; k < kTotalGadgets; ++k) {
            out << (state_.initial_faults[k] ? '1' : '0');
        }
        out << "\n";
        out << state_.trace_events.size() << "\n";
        for (const auto& ev : state_.trace_events) {
            out << ev.step_idx << " " << ev.action_type << " " << ev.target_k << " "
                << static_cast<int>(ev.from_pos.x) << " " << static_cast<int>(ev.from_pos.y) << " "
                << static_cast<int>(ev.to_pos.x) << " " << static_cast<int>(ev.to_pos.y) << " "
                << ev.outcome_code << " " << ev.bracket_lo << " " << ev.bracket_hi << " "
                << ev.true_frontier_k << "\n";
        }
        return true;
    }

    bool load_from_file(const std::string& path) {
        std::ifstream in(path);
        if (!in) return false;
        std::string header;
        std::getline(in, header);
        if (header != "CYBER_VAULT_256_STATE_V3") return false;
        int strict_flag = 0, oracle_flag = 0;
        in >> state_.seed >> state_.scenario_name >> strict_flag >> oracle_flag >> state_.session_resets;
        state_.strict_mode = (strict_flag != 0);
        state_.oracle_hints = (oracle_flag != 0);
        int ax = 4, ay = 32;
        in >> ax >> ay >> state_.avatar_max_reached_k >> state_.keys_held_mask;
        state_.avatar_pos = Coord2D{static_cast<uint8_t>(ax), static_cast<uint8_t>(ay)};
        in >> state_.e2e_runs >> state_.drone_probes >> state_.repairs_attempted
           >> state_.healthy_gadgets_broken >> state_.collateral_induced
           >> state_.verified_prefix_lo >> state_.verified_prefix_hi;
        std::string bits_cur, bits_init;
        in >> bits_cur >> bits_init;
        if (bits_cur.size() != kTotalGadgets || bits_init.size() != kTotalGadgets) return false;
        for (int k = 0; k < kTotalGadgets; ++k) {
            state_.gadget_healthy[k] = (bits_cur[k] == '1');
            state_.initial_faults[k] = (bits_init[k] == '1');
        }
        size_t trace_sz = 0;
        in >> trace_sz;
        state_.trace_events.clear();
        for (size_t i = 0; i < trace_sz; ++i) {
            TraceEvent ev{};
            int fx = 0, fy = 0, tx = 0, ty = 0;
            in >> ev.step_idx >> ev.action_type >> ev.target_k
               >> fx >> fy >> tx >> ty >> ev.outcome_code
               >> ev.bracket_lo >> ev.bracket_hi >> ev.true_frontier_k;
            ev.from_pos = Coord2D{static_cast<uint8_t>(fx), static_cast<uint8_t>(fy)};
            ev.to_pos   = Coord2D{static_cast<uint8_t>(tx), static_cast<uint8_t>(ty)};
            state_.trace_events.push_back(ev);
        }
        recompute_avatar_progress();
        return true;
    }

    std::optional<int> parse_gadget_target(std::string_view token) const {
        if (token.empty()) return std::nullopt;
        std::string cleaned(token);
        if (cleaned.front() == '(' && cleaned.back() == ')') {
            cleaned = cleaned.substr(1, cleaned.size() - 2);
        }
        auto comma = cleaned.find(',');
        if (comma != std::string::npos) {
            try {
                int x = std::stoi(cleaned.substr(0, comma));
                int y = std::stoi(cleaned.substr(comma + 1));
                for (int k = 0; k < kTotalGadgets; ++k) {
                    if (gadgets_[k].pos.x == x && gadgets_[k].pos.y == y) {
                        return k;
                    }
                }
            } catch (...) {
                return std::nullopt;
            }
            return std::nullopt;
        }

        if ((cleaned[0] == 'S' || cleaned[0] == 's') && cleaned.size() >= 4) {
            auto sep = cleaned.find_first_of(":_.");
            if (sep != std::string::npos && sep > 1) {
                try {
                    int sec = std::stoi(cleaned.substr(1, sep - 1));
                    std::string sub_str = cleaned.substr(sep + 1);
                    if (sec < 0 || sec >= kNumSectors || sub_str.empty()) return std::nullopt;
                    char c = static_cast<char>(std::toupper(static_cast<unsigned char>(sub_str[0])));
                    for (int m = 0; m < kGadgetsPerSec; ++m) {
                        if (kSubCodeTags[m][0] == c && sub_str.size() == 1) {
                            return sec * kGadgetsPerSec + m;
                        }
                    }
                    int m = std::stoi(sub_str);
                    if (m >= 0 && m < kGadgetsPerSec) {
                        return sec * kGadgetsPerSec + m;
                    }
                } catch (...) {
                    return std::nullopt;
                }
            }
        }

        try {
            size_t pos = 0;
            int k = std::stoi(cleaned, &pos);
            if (pos == cleaned.size() && k >= 0 && k < kTotalGadgets) {
                return k;
            }
        } catch (...) {
            return std::nullopt;
        }
        return std::nullopt;
    }

    // ========================================================================
    // EXACT BELLMAN-OPTIMAL REFERENCE TRAJECTORY CALCULATOR
    // ========================================================================

    OptimalSolutionPlan compute_optimal_reference_plan() const {
        OptimalSolutionPlan plan{};
        std::array<bool, kTotalGadgets> sim_healthy{};
        for (int k = 0; k < kTotalGadgets; ++k) {
            bool is_init_fault = state_.initial_faults[k];
            sim_healthy[k] = !is_init_fault;
            if (is_init_fault) {
                plan.initial_fault_ks.push_back(k);
            }
        }

        auto sim_frontier = [&]() -> int {
            for (int k = 0; k < kTotalGadgets; ++k) {
                if (!sim_healthy[k]) return k;
            }
            return kAllCleared;
        };

        int verified_lo = 0;
        int wave = 1;
        int step_counter = 0;
        Coord2D cur_pos{4, 32};

        while (true) {
            int lo = verified_lo;
            int hi = kTotalGadgets;

            if (lo > 0) {
                step_counter++;
                plan.total_probes++;
                int k_star = sim_frontier();
                bool all_clear = (k_star > kTotalGadgets - 1);
                Coord2D target_pos = gadgets_[kTotalGadgets - 1].pos;
                plan.steps.push_back(OptimalStep{
                    .step_idx     = step_counter,
                    .wave_idx     = wave,
                    .action_type  = "OPT_PROBE",
                    .target_k     = kTotalGadgets - 1,
                    .from_pos     = cur_pos,
                    .to_pos       = target_pos,
                    .outcome_code = all_clear ? "PASS_1_ALL_CLEAR" : "BLOCKED_0",
                    .bracket_lo   = lo,
                    .bracket_hi   = all_clear ? kAllCleared : (kTotalGadgets - 1),
                    .shannon_bits = std::log2(static_cast<double>(hi - lo + 1))
                });
                cur_pos = target_pos;
                if (all_clear) {
                    break;
                }
                hi = kTotalGadgets - 1;
            }

            while (lo < hi) {
                int w = hi - lo + 1;
                int split_l = bellman_split_[w];
                int m = lo + split_l - 1;
                step_counter++;
                plan.total_probes++;
                int k_star = sim_frontier();
                bool pass = (k_star > m);
                if (pass) {
                    lo = m + 1;
                } else {
                    hi = m;
                }
                Coord2D target_pos = gadgets_[m].pos;
                plan.steps.push_back(OptimalStep{
                    .step_idx     = step_counter,
                    .wave_idx     = wave,
                    .action_type  = "OPT_PROBE",
                    .target_k     = m,
                    .from_pos     = cur_pos,
                    .to_pos       = target_pos,
                    .outcome_code = pass ? "PASS_1" : "BLOCKED_0",
                    .bracket_lo   = lo,
                    .bracket_hi   = hi,
                    .shannon_bits = std::log2(static_cast<double>(w))
                });
                cur_pos = target_pos;
            }

            if (lo == kAllCleared) {
                break;
            }

            step_counter++;
            plan.total_repairs++;
            sim_healthy[lo] = true;
            Coord2D repair_pos = gadgets_[lo].pos;
            plan.steps.push_back(OptimalStep{
                .step_idx     = step_counter,
                .wave_idx     = wave,
                .action_type  = "OPT_REPAIR",
                .target_k     = lo,
                .from_pos     = cur_pos,
                .to_pos       = repair_pos,
                .outcome_code = "SURGICAL_REPAIR_SUCCESS",
                .bracket_lo   = lo + 1,
                .bracket_hi   = kTotalGadgets,
                .shannon_bits = 0.0
            });
            cur_pos = repair_pos;
            verified_lo = lo + 1;
            wave++;
        }

        return plan;
    }

    // Joint Symptom-Filtered Subspace Optimal Reference Trajectory (O_e2e^{-1}(o) + Pi)
    OptimalSolutionPlan compute_joint_optimal_reference_plan() const {
        OptimalSolutionPlan plan{};
        std::array<bool, kTotalGadgets> sim_healthy{};
        for (int k = 0; k < kTotalGadgets; ++k) {
            bool is_init_fault = state_.initial_faults[k];
            sim_healthy[k] = !is_init_fault;
            if (is_init_fault) {
                plan.initial_fault_ks.push_back(k);
            }
        }

        auto sim_frontier = [&]() -> int {
            for (int k = 0; k < kTotalGadgets; ++k) {
                if (!sim_healthy[k]) return k;
            }
            return kAllCleared;
        };

        int verified_lo = 0;
        int wave = 1;
        int step_counter = 0;
        Coord2D cur_pos{4, 32};

        while (true) {
            if (verified_lo >= kTotalGadgets) {
                break;
            }

            // 1. End-to-End Symptom Probe at k=127 to check full chain & extract coarse symptom o
            step_counter++;
            plan.total_probes++;
            int k_star = sim_frontier();
            bool all_clear = (k_star > kTotalGadgets - 1);
            Coord2D end_pos = gadgets_[kTotalGadgets - 1].pos;
            ObsSymptom sym = all_clear ? ObsSymptom::Victory : gadgets_[k_star].aliased_symptom;

            plan.steps.push_back(OptimalStep{
                .step_idx     = step_counter,
                .wave_idx     = wave,
                .action_type  = "JOINT_E2E_PROBE",
                .target_k     = kTotalGadgets - 1,
                .from_pos     = cur_pos,
                .to_pos       = end_pos,
                .outcome_code = all_clear ? "PASS_1_ALL_CLEAR" : std::string(symptom_code_str(sym)),
                .bracket_lo   = verified_lo,
                .bracket_hi   = all_clear ? kAllCleared : (kTotalGadgets - 1),
                .shannon_bits = std::log2(static_cast<double>(kTotalGadgets - verified_lo + 1))
            });
            cur_pos = end_pos;
            if (all_clear) {
                break;
            }

            // 2. Project active suffix [verified_lo .. 127] onto Kronecker Symptom Fiber F(sym, verified_lo)
            std::vector<int> fiber;
            for (int k = verified_lo; k < kTotalGadgets; ++k) {
                if (gadgets_[k].aliased_symptom == sym) {
                    fiber.push_back(k);
                }
            }

            // 3. Bellman-Optimal Bisection strictly over the ordered Symptom Fiber
            int lo_idx = 0;
            int hi_idx = static_cast<int>(fiber.size()) - 1;
            while (lo_idx < hi_idx) {
                int w_f = hi_idx - lo_idx + 1;
                int split_l = bellman_split_[w_f];
                int mid_idx = lo_idx + split_l - 1;
                int m = fiber[mid_idx];

                step_counter++;
                plan.total_probes++;
                bool pass = (k_star > m);
                if (pass) {
                    lo_idx = mid_idx + 1;
                } else {
                    hi_idx = mid_idx;
                }
                Coord2D target_pos = gadgets_[m].pos;
                plan.steps.push_back(OptimalStep{
                    .step_idx     = step_counter,
                    .wave_idx     = wave,
                    .action_type  = "JOINT_FIBER_PROBE",
                    .target_k     = m,
                    .from_pos     = cur_pos,
                    .to_pos       = target_pos,
                    .outcome_code = pass ? "PASS_1" : "BLOCKED_0",
                    .bracket_lo   = fiber[lo_idx],
                    .bracket_hi   = fiber[hi_idx],
                    .shannon_bits = std::log2(static_cast<double>(w_f))
                });
                cur_pos = target_pos;
            }

            int isolated_k = fiber[lo_idx];
            step_counter++;
            plan.total_repairs++;
            sim_healthy[isolated_k] = true;
            Coord2D repair_pos = gadgets_[isolated_k].pos;
            plan.steps.push_back(OptimalStep{
                .step_idx     = step_counter,
                .wave_idx     = wave,
                .action_type  = "OPT_REPAIR",
                .target_k     = isolated_k,
                .from_pos     = cur_pos,
                .to_pos       = repair_pos,
                .outcome_code = "SURGICAL_REPAIR_SUCCESS",
                .bracket_lo   = isolated_k + 1,
                .bracket_hi   = kTotalGadgets,
                .shannon_bits = 0.0
            });
            cur_pos = repair_pos;
            verified_lo = isolated_k + 1;
            wave++;
        }

        return plan;
    }

    // ========================================================================
    // GAME COMMAND IMPLEMENTATIONS (WITH REAL-LIFE SSH FIDELITY)
    // ========================================================================

    // 1. End-to-End Transit (`ssh scada-plc-unit04`)
    std::string cmd_run_e2e(bool json_mode) {
        Coord2D prev_pos = state_.avatar_pos;
        state_.e2e_runs++;
        int k_star = recompute_avatar_progress();
        ObsSymptom sym = (k_star == kAllCleared)
                             ? ObsSymptom::Victory
                             : gadgets_[k_star].aliased_symptom;

        Coord2D end_pos = (k_star == kAllCleared) ? Coord2D{61, 224} : gadgets_[k_star].pos;
        record_trace("RUN_E2E", -1, prev_pos, end_pos, std::string(symptom_code_str(sym)), k_star);

        std::ostringstream oss;
        if (json_mode) {
            oss << "{\n"
                << "  \"action\": \"run_e2e\",\n"
                << "  \"victory\": " << (k_star == kAllCleared ? "true" : "false") << ",\n"
                << "  \"symptom_code\": \"" << symptom_code_str(sym) << "\",\n"
                << "  \"symptom_banner\": \"" << json_escape(symptom_human_banner(sym)) << "\"\n"
                << "}\n";
            return oss.str();
        }

        oss << "========================================================================\n"
            << " [END-TO-END AVATAR TRANSIT ATTEMPT #" << state_.e2e_runs << " -> Sector S15 (scada-plc-unit04)]\n"
            << "========================================================================\n"
            << "  Telemetry Code : " << symptom_code_str(sym) << "\n"
            << "  Observation    : " << symptom_human_banner(sym) << "\n";
        if (k_star == kAllCleared) {
            oss << "  Keys Collected : 16 / 16 (0xFFFF)\n"
                << "  Avatar Position: (61, 224) [SCADA CORE 'X' IN SECTOR 15]\n";
        }
        return oss.str();
    }

    // 2. Controlled Non-Interactive Prefix Probe (`probe <target>`)
    //    Isomorphic to `ssh -o BatchMode=yes -o IdentitiesOnly=yes -o ForwardAgent=no <target>`
    std::string cmd_drone_probe(int m_target, bool json_mode) {
        Coord2D prev_pos = state_.avatar_pos;
        state_.drone_probes++;
        int k_star = recompute_avatar_progress();
        bool passed = (k_star > m_target);
        const auto& g = gadgets_[m_target];

        if (passed) {
            if (m_target + 1 > state_.verified_prefix_lo) {
                state_.verified_prefix_lo = m_target + 1;
            }
        } else {
            if (m_target < state_.verified_prefix_hi) {
                state_.verified_prefix_hi = m_target;
            }
        }

        state_.avatar_pos = g.pos;
        ObsSymptom obs_sym = passed ? ObsSymptom::Victory : gadgets_[k_star].aliased_symptom;
        record_trace("PROBE", m_target, prev_pos, g.pos, passed ? "PASS_1" : "BLOCKED_0", k_star);

        std::ostringstream oss;
        if (json_mode) {
            oss << "{\n"
                << "  \"action\": \"probe\",\n"
                << "  \"target_k\": " << m_target << ",\n"
                << "  \"sector\": " << g.sector_i << ",\n"
                << "  \"substage_m\": " << g.sub_m << ",\n"
                << "  \"coord\": [" << static_cast<int>(g.pos.x) << ", " << static_cast<int>(g.pos.y) << "],\n"
                << "  \"gadget_name\": \"" << g.game_name << "\",\n"
                << "  \"ssh_equivalent\": \"" << g.ssh_equivalent << "\",\n"
                << "  \"probe_result_bit\": " << (passed ? 1 : 0) << ",\n"
                << "  \"observed_symptom\": \"" << (passed ? "CLEAR_OK" : symptom_code_str(obs_sym)) << "\"\n"
                << "}\n";
            return oss.str();
        }

        oss << "------------------------------------------------------------------------\n"
            << " [CONTROLLED NON-INTERACTIVE DRONE PROBE -> k=" << m_target
            << " | Sector S" << g.sector_i << " (" << kSectorHostnames[g.sector_i]
            << "), m=" << g.sub_m << "]\n"
            << "------------------------------------------------------------------------\n"
            << "  Target Waypoint : (" << static_cast<int>(g.pos.x) << ", " << static_cast<int>(g.pos.y)
            << ") [" << g.code_tag << ": " << g.game_name << "]\n"
            << "  SSH Equivalent  : " << g.ssh_equivalent << "\n"
            << "  Probe Outcome   : " << (passed
                   ? "PASS [Bit = 1] -> Drone reached (" + std::to_string(g.pos.x) + "," +
                     std::to_string(g.pos.y) + ") and cleared stage k=" + std::to_string(m_target) + "."
                   : "BLOCKED [Bit = 0] -> Probe aborted before clearing k=" + std::to_string(m_target) +
                     " with symptom: " + std::string(symptom_code_str(obs_sym))) << "\n";

        if (state_.oracle_hints) {
            oss << "  [Oracle Hint]   : Active Bracket k* in [" << state_.verified_prefix_lo << " .. "
                << state_.verified_prefix_hi << "]\n";
        }
        return oss.str();
    }

    // 3. Mixed-Mode ProxyJump Probe (`probe-mixed <target>`)
    //    Isomorphic to the classic OpenSSH `ProxyJump` diagnostic flaw:
    //    When the operator runs `ssh -o BatchMode=yes <hop_i>`, OpenSSH applies `-o BatchMode=yes`
    //    ONLY to the final target hop_i, while upstream ProxyJump subprocesses (0..i-1) run
    //    interactively (`BatchMode=no`, prompting `/dev/tty` to unlock Key_0..Key_{i-1}),
    //    and then the target hop_i fails with `Permission denied (publickey)` because the
    //    encrypted key file cannot be unlocked under `BatchMode=yes` at hop_i!
    std::string cmd_mixed_mode_probe(int m_target, bool json_mode) {
        Coord2D prev_pos = state_.avatar_pos;
        state_.drone_probes++;
        const auto& g = gadgets_[m_target];
        int target_sec = g.sector_i;

        // Simulate mixed-mode traversal:
        // Upstream sectors 0 .. target_sec-1 bypass m=1 (Key Safe / Passphrase) interactively,
        // UNLESS they hit a non-passphrase fault (m != 1).
        // At target_sec, `BatchMode=yes` is enforced, so if Key Safe k=1 (S0:1) is still locked
        // in the agent, the target sector's Blast Door (m=6) or Safe (m=1) rejects the key,
        // producing a misleading "O_2_CREDENTIAL_KEY_REJECTED at Sector S_{target_sec}"!
        int halted_k = kAllCleared;
        bool false_positive_at_target = false;

        for (int k = 0; k <= m_target; ++k) {
            int sec = k / kGadgetsPerSec;
            int sub = k % kGadgetsPerSec;
            if (!state_.gadget_healthy[k]) {
                if (sub == 1 && sec < target_sec) {
                    // Upstream interactive `/dev/tty` passphrase prompt masks the locked safe!
                    continue;
                }
                halted_k = k;
                break;
            }
        }

        // If upstream passed via interactive prompt, but S0:1 (k=1) is actually locked in the agent,
        // and m_target reaches the target sector's auth stage (m >= 1 in target_sec), it fails at target_sec!
        if (halted_k == kAllCleared && !state_.gadget_healthy[1] && target_sec > 0 && g.sub_m >= 1) {
            halted_k = target_sec * kGadgetsPerSec + 6; // Misleading failure at target Blast Door D_{target_sec}!
            false_positive_at_target = true;
        }

        bool passed = (halted_k == kAllCleared);
        state_.avatar_pos = g.pos;
        record_trace("PROBE_MIXED", m_target, prev_pos, g.pos,
                     passed ? "MIXED_PASS_1" : (false_positive_at_target ? "MIXED_FALSE_POSITIVE_O2" : "MIXED_BLOCKED_0"),
                     recompute_avatar_progress());

        std::ostringstream oss;
        if (json_mode) {
            oss << "{\n"
                << "  \"action\": \"probe_mixed\",\n"
                << "  \"target_k\": " << m_target << ",\n"
                << "  \"probe_result_bit\": " << (passed ? 1 : 0) << ",\n"
                << "  \"reported_halt_sector\": " << (passed ? -1 : (halted_k / kGadgetsPerSec)) << ",\n"
                << "  \"symptom_code\": \"" << (passed ? "CLEAR_OK" : "O_2_CREDENTIAL_KEY_REJECTED") << "\"\n"
                << "}\n";
            return oss.str();
        }

        oss << "------------------------------------------------------------------------\n"
            << " [MIXED-MODE PROXYJUMP PROBE (Interactive Upstream + BatchMode Target) -> k=" << m_target << "]\n"
            << "------------------------------------------------------------------------\n"
            << "  Target Sector   : S" << g.sector_i << " (" << kSectorHostnames[g.sector_i] << ")\n";
        if (passed) {
            oss << "  Probe Outcome   : PASS [Bit = 1] (Note: upstream sectors used interactive /dev/tty bypass!)\n";
        } else if (false_positive_at_target) {
            oss << "  Probe Outcome   : BLOCKED [Bit = 0] at Sector S" << target_sec << " (" << kSectorHostnames[target_sec] << ")!\n"
                << "  Reported Error  : " << kSectorHostnames[target_sec] << ": Permission denied (publickey) [O_2_CREDENTIAL_KEY_REJECTED]\n"
                << "  [Methodological Warning]: Upstream sectors S0..S" << (target_sec - 1)
                << " prompted interactively for the safe passcode, whereas target S" << target_sec
                << " enforced BatchMode=yes! Do NOT blindly assume S" << target_sec << "'s Blast Door is broken!\n";
        } else {
            ObsSymptom sym = gadgets_[halted_k].aliased_symptom;
            oss << "  Probe Outcome   : BLOCKED [Bit = 0] -> " << symptom_code_str(sym) << "\n";
        }
        return oss.str();
    }

    // 4. Physically Enter & Inspect Room (`inspect <target>`)
    std::string cmd_inspect_room(int k_target, bool json_mode) {
        Coord2D prev_pos = state_.avatar_pos;
        int k_star = recompute_avatar_progress();
        const auto& g = gadgets_[k_target];

        if (k_target > k_star) {
            record_trace("INSPECT", k_target, prev_pos, g.pos, "FOG_OF_WAR_BLOCKED", k_star);
            std::ostringstream oss;
            if (json_mode) {
                oss << "{\n"
                    << "  \"action\": \"inspect\",\n"
                    << "  \"target_k\": " << k_target << ",\n"
                    << "  \"reachable\": false,\n"
                    << "  \"error\": \"FOG_OF_WAR_UNREACHABLE\"\n"
                    << "}\n";
                return oss.str();
            }
            oss << "========================================================================\n"
                << " [FOG-OF-WAR ACCESS DENIED: CANNOT ENTER ROOM k=" << k_target
                << " AT (" << static_cast<int>(g.pos.x) << ", " << static_cast<int>(g.pos.y) << ")]\n"
                << "========================================================================\n"
                << "  Causal Censoring: Your avatar cannot physically reach Sector S" << g.sector_i
                << " (" << g.game_name << ")\n"
                << "                    because an UPSTREAM gate in [0 .. " << (k_target - 1)
                << "] is currently blocking transit!\n";
            return oss.str();
        }

        state_.avatar_pos = g.pos;
        bool healthy = state_.gadget_healthy[k_target];
        if (healthy && k_target + 1 > state_.verified_prefix_lo) {
            state_.verified_prefix_lo = k_target + 1;
        } else if (!healthy) {
            state_.verified_prefix_lo = k_target;
            state_.verified_prefix_hi = k_target;
        }

        record_trace("INSPECT", k_target, prev_pos, g.pos, healthy ? "INSPECT_HEALTHY" : "INSPECT_FAULTY", k_star);

        std::ostringstream oss;
        if (json_mode) {
            oss << "{\n"
                << "  \"action\": \"inspect\",\n"
                << "  \"target_k\": " << k_target << ",\n"
                << "  \"reachable\": true,\n"
                << "  \"sector\": " << g.sector_i << ",\n"
                << "  \"substage_m\": " << g.sub_m << ",\n"
                << "  \"coord\": [" << static_cast<int>(g.pos.x) << ", " << static_cast<int>(g.pos.y) << "],\n"
                << "  \"gadget_name\": \"" << g.game_name << "\",\n"
                << "  \"ssh_equivalent\": \"" << g.ssh_equivalent << "\",\n"
                << "  \"healthy\": " << (healthy ? "true" : "false") << ",\n"
                << "  \"observation\": \"" << json_escape(healthy ? g.inspect_healthy_msg : g.inspect_faulty_msg) << "\"\n"
                << "}\n";
            return oss.str();
        }

        oss << "========================================================================\n"
            << " [ROOM ENTRY & LOCAL INSPECTION: k=" << k_target << " | Sector S" << g.sector_i
            << " (" << kSectorHostnames[g.sector_i] << ") | m=" << g.sub_m << "]\n"
            << "========================================================================\n"
            << "  Avatar Position : (" << static_cast<int>(g.pos.x) << ", " << static_cast<int>(g.pos.y)
            << ") inside bounding box [(" << static_cast<int>(g.room_min.x) << "," << static_cast<int>(g.room_min.y)
            << ")..(" << static_cast<int>(g.room_max.x) << "," << static_cast<int>(g.room_max.y) << ")]\n"
            << "  2D Room Gadget  : [" << g.code_tag << "] " << g.game_name << "\n"
            << "  SSH Equivalent  : " << g.ssh_equivalent << "\n"
            << "  Room Layout     : " << g.room_description << "\n"
            << "  Physical Status : " << (healthy ? "OPERATIONAL (GREEN)" : "FAULTY / JAMMED (RED)") << "\n"
            << "  Direct Finding  : " << (healthy ? g.inspect_healthy_msg : g.inspect_faulty_msg) << "\n";
        return oss.str();
    }

    // 5. Repair / Mutate Gadget (`repair <target>`)
    //    Realistic SSH fidelity: Repairing stage k does NOT reveal whether downstream
    //    stages k+1..127 are clear! The operator must explicitly test downstream via `probe` or `run`.
    std::string cmd_repair_gadget(int k_target, bool json_mode) {
        Coord2D prev_pos = state_.avatar_pos;
        state_.repairs_attempted++;
        int k_star = recompute_avatar_progress();
        const auto& g = gadgets_[k_target];

        bool was_healthy = state_.gadget_healthy[k_target];
        bool is_frontier = (k_target == k_star);

        std::string status_tag;
        std::string detail_msg;

        if (is_frontier && !was_healthy) {
            state_.gadget_healthy[k_target] = true;
            recompute_avatar_progress();
            state_.verified_prefix_lo = k_target + 1;
            state_.verified_prefix_hi = kTotalGadgets;
            state_.avatar_pos = g.pos;
            status_tag = "SURGICAL_REPAIR_SUCCESS";
            detail_msg = "Restored faulty gadget k=" + std::to_string(k_target) +
                         " (" + std::string(g.game_name) + ") in Sector S" +
                         std::to_string(g.sector_i) + " (" + std::string(kSectorHostnames[g.sector_i]) +
                         "). Downstream path beyond k=" + std::to_string(k_target) +
                         " is now unmasked — run `probe` or `run` to verify downstream transit.";
        } else if (was_healthy) {
            state_.healthy_gadgets_broken++;
            if (state_.strict_mode) {
                state_.gadget_healthy[k_target] = false;
                state_.collateral_induced++;
                recompute_avatar_progress();
                state_.verified_prefix_lo = std::min(state_.verified_prefix_lo, k_target);
                status_tag = "BLIND_EDIT_BROKE_HEALTHY_GADGET";
                detail_msg = "COLLATERAL DAMAGE: Gadget k=" + std::to_string(k_target) +
                             " in Sector S" + std::to_string(g.sector_i) +
                             " was HEALTHY! Blind configuration mutation broke it (state toggled 1 -> 0)!";
            } else {
                status_tag = "UNNECESSARY_REPAIR_ON_HEALTHY_GADGET";
                detail_msg = "WARNING: Gadget k=" + std::to_string(k_target) +
                             " at (" + std::to_string(g.pos.x) + "," + std::to_string(g.pos.y) +
                             ") was already HEALTHY! Unverified mutation recorded in metrics.";
            }
        } else {
            state_.healthy_gadgets_broken++;
            status_tag = "UNREACHABLE_DOWNSTREAM_REPAIR_REJECTED";
            detail_msg = "BLOCKED BY FOG-OF-WAR: Cannot reach or modify k=" + std::to_string(k_target) +
                         " in Sector S" + std::to_string(g.sector_i) +
                         " while an upstream gate is still blocking transit!";
        }

        record_trace("REPAIR", k_target, prev_pos, g.pos, status_tag, recompute_avatar_progress());

        std::ostringstream oss;
        if (json_mode) {
            oss << "{\n"
                << "  \"action\": \"repair\",\n"
                << "  \"target_k\": " << k_target << ",\n"
                << "  \"status\": \"" << status_tag << "\",\n"
                << "  \"message\": \"" << json_escape(detail_msg) << "\",\n"
                << "  \"metrics\": {\n"
                << "    \"drone_probes\": " << state_.drone_probes << ",\n"
                << "    \"repairs_attempted\": " << state_.repairs_attempted << ",\n"
                << "    \"wrong_repairs\": " << state_.healthy_gadgets_broken << "\n"
                << "  }\n"
                << "}\n";
            return oss.str();
        }

        oss << "========================================================================\n"
            << " [REPAIR INTERVENTION AT k=" << k_target << " | Sector S" << g.sector_i
            << " (" << kSectorHostnames[g.sector_i] << ") | ("
            << static_cast<int>(g.pos.x) << ", " << static_cast<int>(g.pos.y) << ")]\n"
            << "========================================================================\n"
            << "  Target Gadget : [" << g.code_tag << "] " << g.game_name << "\n"
            << "  SSH Equivalent: " << g.ssh_equivalent << "\n"
            << "  Outcome       : " << status_tag << "\n"
            << "  Details       : " << detail_msg << "\n";
        return oss.str();
    }

    std::string cmd_render_map(std::optional<int> zoom_sector) {
        recompute_avatar_progress();
        std::ostringstream oss;

        if (!zoom_sector.has_value()) {
            oss << "========================================================================\n"
                << " 256x256 CYBER-VAULT 2D BOARD OVERVIEW (4x4 Boustrophedon Sector Grid)\n"
                << "========================================================================\n";

            for (int row = 0; row < kSectorGrid; ++row) {
                oss << "  ";
                for (int col = 0; col < kSectorGrid; ++col) {
                    oss << "+----------------";
                }
                oss << "+\n  ";
                for (int col = 0; col < kSectorGrid; ++col) {
                    int sec = (row % 2 == 0) ? (row * kSectorGrid + col)
                                             : (row * kSectorGrid + (kSectorGrid - 1 - col));
                    Coord2D orig = sector_origin(sec);
                    oss << "| S" << std::left << std::setw(2) << sec
                        << " (" << std::setw(3) << static_cast<int>(orig.x) << ","
                        << std::setw(3) << static_cast<int>(orig.y) << ") ";
                }
                oss << "|\n  ";
                for (int col = 0; col < kSectorGrid; ++col) {
                    int sec = (row % 2 == 0) ? (row * kSectorGrid + col)
                                             : (row * kSectorGrid + (kSectorGrid - 1 - col));
                    oss << "| " << std::left << std::setw(14) << kSectorHostnames[sec].substr(0, 14) << " ";
                }
                oss << "|\n  ";
                for (int col = 0; col < kSectorGrid; ++col) {
                    int sec = (row % 2 == 0) ? (row * kSectorGrid + col)
                                             : (row * kSectorGrid + (kSectorGrid - 1 - col));
                    int k_start = sec * kGadgetsPerSec;
                    int k_end   = k_start + kGadgetsPerSec - 1;
                    std::string badge = "stages " + std::to_string(k_start) + ".." + std::to_string(k_end);
                    badge.resize(14, ' ');
                    oss << "| " << badge << " ";
                }
                oss << "|\n";
            }
            oss << "  ";
            for (int col = 0; col < kSectorGrid; ++col) {
                oss << "+----------------";
            }
            oss << "+\n";
            oss << "  Tip: Run `map <sector_0_to_15>` to render the detailed 64x64 room layout of a sector.\n";
            return oss.str();
        }

        int sec = *zoom_sector;
        if (sec < 0 || sec >= kNumSectors) {
            return "Error: Sector index must be between 0 and 15.\n";
        }
        Coord2D orig = sector_origin(sec);
        int k_base = sec * kGadgetsPerSec;

        oss << "========================================================================\n"
            << " SECTOR S" << sec << " (" << kSectorHostnames[sec] << ") | 64x64 Tile Origin=("
            << static_cast<int>(orig.x) << "," << static_cast<int>(orig.y)
            << ") | Stages k=" << k_base << ".." << (k_base + 7) << "\n"
            << "========================================================================\n";

        for (int ly = 6; ly <= 56; ly += 2) {
            oss << "  y=" << std::setw(3) << (static_cast<int>(orig.y) + ly) << " | ";
            for (int lx = 2; lx <= 62; ++lx) {
                int gx = orig.x + lx;
                int gy = orig.y + ly;
                if (std::abs(static_cast<int>(state_.avatar_pos.x) - gx) <= 0 &&
                    std::abs(static_cast<int>(state_.avatar_pos.y) - gy) <= 1) {
                    oss << '@';
                    continue;
                }
                char ch = static_cast<char>(grid_[gy][gx]);
                for (int m = 0; m < kGadgetsPerSec; ++m) {
                    const auto& g = gadgets_[k_base + m];
                    if (g.pos.x == gx && std::abs(static_cast<int>(g.pos.y) - gy) <= 1) {
                        ch = static_cast<char>(g.glyph);
                        break;
                    }
                }
                oss << ch;
            }
            oss << "\n";
        }

        oss << "\n  Gadgets in Sector S" << sec << " (" << kSectorHostnames[sec] << "):\n";
        for (int m = 0; m < kGadgetsPerSec; ++m) {
            int k = k_base + m;
            const auto& g = gadgets_[k];
            oss << "    k=" << std::setw(3) << k << " [S" << sec << ":" << m << " '" << g.code_tag << "'] @ ("
                << std::setw(3) << static_cast<int>(g.pos.x) << ","
                << std::setw(3) << static_cast<int>(g.pos.y) << ") : "
                << std::left << std::setw(42) << g.game_name.substr(0, 42)
                << " (" << g.ssh_equivalent << ")\n";
        }
        return oss.str();
    }

    std::string cmd_bellman_hint(bool json_mode) {
        int lo = state_.verified_prefix_lo;
        int hi = state_.verified_prefix_hi;
        int width = hi - lo + 1;

        std::ostringstream oss;
        if (lo >= kTotalGadgets && recompute_avatar_progress() == kAllCleared) {
            if (json_mode) {
                return "{ \"action\": \"hint\", \"status\": \"ALREADY_SOLVED\", \"recommended_command\": \"export\" }\n";
            }
            return "Bellman Advisor: All 128 rooms are operational and the SCADA Core is reached! Run `export`.\n";
        }

        if (width <= 1) {
            int k_iso = lo;
            const auto& g = gadgets_[k_iso];
            if (json_mode) {
                oss << "{\n"
                    << "  \"action\": \"hint\",\n"
                    << "  \"bracket_width\": 1,\n"
                    << "  \"isolated_k\": " << k_iso << ",\n"
                    << "  \"coord\": [" << static_cast<int>(g.pos.x) << ", " << static_cast<int>(g.pos.y) << "],\n"
                    << "  \"recommended_command\": \"repair " << k_iso << "\"\n"
                    << "}\n";
                return oss.str();
            }
            oss << "========================================================================\n"
                << " [BELLMAN-OPTIMAL ADVISOR: FRONTIER ISOLATED (W = 1)]\n"
                << "========================================================================\n"
                << "  Active Bracket      : [" << lo << " .. " << hi << "] (Exact match: k* = " << k_iso << ")\n"
                << "  Target Coordinates  : (" << static_cast<int>(g.pos.x) << ", " << static_cast<int>(g.pos.y)
                << ") in Sector S" << g.sector_i << " (" << g.game_name << ")\n"
                << "  Recommended Command : `repair " << k_iso << "` (or `inspect " << k_iso << "` first)\n";
            return oss.str();
        }

        int split_l = bellman_split_[width];
        int m_opt = lo + split_l - 1;
        const auto& g = gadgets_[m_opt];
        double exp_probes = bellman_cost_[width];
        double shannon_bits = std::log2(static_cast<double>(width));

        if (json_mode) {
            oss << "{\n"
                << "  \"action\": \"hint\",\n"
                << "  \"bracket_interval\": [" << lo << ", " << hi << "],\n"
                << "  \"bracket_width\": " << width << ",\n"
                << "  \"shannon_entropy_bits\": " << std::fixed << std::setprecision(4) << shannon_bits << ",\n"
                << "  \"bellman_expected_probes\": " << exp_probes << ",\n"
                << "  \"optimal_probe_k\": " << m_opt << ",\n"
                << "  \"optimal_probe_coord\": [" << static_cast<int>(g.pos.x) << ", " << static_cast<int>(g.pos.y) << "],\n"
                << "  \"recommended_command\": \"probe " << m_opt << "\"\n"
                << "}\n";
            return oss.str();
        }

        oss << "========================================================================\n"
            << " [BELLMAN-OPTIMAL DYNAMIC PROGRAMMING ADVISOR]\n"
            << "========================================================================\n"
            << "  Current Ambiguity Bracket : k* in [" << lo << " .. " << hi << "] (Width W = " << width << ")\n"
            << "  Shannon Entropy H(W)      : " << std::fixed << std::setprecision(4) << shannon_bits << " bits\n"
            << "  Bellman Optimal V(W)      : " << exp_probes << " expected probes to isolate k*\n"
            << "  Optimal Midpoint Split    : L* = " << split_l << " -> Probe k = " << m_opt << "\n"
            << "  2D Waypoint Coordinates   : (" << static_cast<int>(g.pos.x) << ", " << static_cast<int>(g.pos.y)
            << ") [Sector S" << g.sector_i << ", m=" << g.sub_m << ": " << g.game_name << "]\n"
            << "  Recommended Next Command  : `probe " << m_opt << "`\n";
        return oss.str();
    }

    std::string cmd_autosolve(bool json_mode) {
        std::ostringstream trace;
        int rounds = 0;

        while (true) {
            int lo = state_.verified_prefix_lo;
            if (lo >= kTotalGadgets) {
                break;
            }

            // 1. End-to-End Symptom Check at k=127 (or E2E run)
            Coord2D prev_pos = state_.avatar_pos;
            state_.drone_probes++;
            int k_star = recompute_avatar_progress();
            bool all_ok = (k_star > kTotalGadgets - 1);
            state_.avatar_pos = gadgets_[kTotalGadgets - 1].pos;
            ObsSymptom sym = all_ok ? ObsSymptom::Victory : gadgets_[k_star].aliased_symptom;
            record_trace("PROBE", kTotalGadgets - 1, prev_pos, state_.avatar_pos,
                         all_ok ? "PASS_1" : "BLOCKED_0", k_star);
            if (all_ok) {
                state_.verified_prefix_lo = kAllCleared;
                state_.verified_prefix_hi = kAllCleared;
                break;
            }
            state_.verified_prefix_hi = kTotalGadgets - 1;

            // 2. Project active suffix [lo .. 127] onto Kronecker Symptom Fiber F(sym, lo)
            std::vector<int> fiber;
            for (int k = lo; k < kTotalGadgets; ++k) {
                if (gadgets_[k].aliased_symptom == sym) {
                    fiber.push_back(k);
                }
            }

            // 3. Bellman-Optimal Bisection strictly over the ordered Symptom Fiber
            int lo_idx = 0;
            int hi_idx = static_cast<int>(fiber.size()) - 1;
            while (lo_idx < hi_idx) {
                int w_f = hi_idx - lo_idx + 1;
                int split_l = bellman_split_[w_f];
                int mid_idx = lo_idx + split_l - 1;
                int m = fiber[mid_idx];
                prev_pos = state_.avatar_pos;
                state_.drone_probes++;
                k_star = recompute_avatar_progress();
                bool pass = (k_star > m);
                if (pass) {
                    lo_idx = mid_idx + 1;
                    if (m + 1 > state_.verified_prefix_lo) state_.verified_prefix_lo = m + 1;
                } else {
                    hi_idx = mid_idx;
                    if (m < state_.verified_prefix_hi) state_.verified_prefix_hi = m;
                }
                state_.avatar_pos = gadgets_[m].pos;
                record_trace("PROBE", m, prev_pos, state_.avatar_pos,
                             pass ? "PASS_1" : "BLOCKED_0", k_star);
            }

            int isolated_k = fiber[lo_idx];
            rounds++;
            const auto& g = gadgets_[isolated_k];
            prev_pos = state_.avatar_pos;
            state_.repairs_attempted++;
            state_.gadget_healthy[isolated_k] = true;
            state_.verified_prefix_lo = isolated_k + 1;
            state_.verified_prefix_hi = kTotalGadgets;
            state_.avatar_pos = g.pos;
            int new_k_star = recompute_avatar_progress();
            record_trace("REPAIR", isolated_k, prev_pos, g.pos, "SURGICAL_REPAIR_SUCCESS", new_k_star);

            trace << "  [Wave " << rounds << "] Symptom " << symptom_code_str(sym)
                  << " (" << fiber.size() << " fiber rooms) -> Isolated k*=" << isolated_k
                  << " @ (" << static_cast<int>(g.pos.x) << "," << static_cast<int>(g.pos.y)
                  << ") [S" << g.sector_i << ":" << g.sub_m << " " << g.game_name
                  << "] -> Surgically Repaired!\n";
        }

        int final_k = recompute_avatar_progress();
        std::ostringstream oss;
        if (json_mode) {
            oss << "{\n"
                << "  \"action\": \"autosolve\",\n"
                << "  \"victory\": " << (final_k == kAllCleared ? "true" : "false") << ",\n"
                << "  \"waves_repaired\": " << rounds << ",\n"
                << "  \"total_drone_probes\": " << state_.drone_probes << ",\n"
                << "  \"total_repairs\": " << state_.repairs_attempted << ",\n"
                << "  \"wrong_repairs\": " << state_.healthy_gadgets_broken << "\n"
                << "}\n";
            return oss.str();
        }

        oss << "========================================================================\n"
            << " [BELLMAN-OPTIMAL AUTOSOLVER EXECUTION TRACE]\n"
            << "========================================================================\n"
            << trace.str()
            << "------------------------------------------------------------------------\n"
            << "  Result         : " << (final_k == kAllCleared ? "VICTORY (SCADA CORE REACHED)" : "INCOMPLETE") << "\n"
            << "  Drone Probes   : " << state_.drone_probes << "\n"
            << "  Surgical Fixes : " << state_.repairs_attempted << "\n"
            << "  Wrong Repairs  : " << state_.healthy_gadgets_broken << "\n";
        return oss.str();
    }

    std::string cmd_status(bool json_mode) {
        int k_star = recompute_avatar_progress();
        bool won = (k_star == kAllCleared);

        std::ostringstream oss;
        if (json_mode) {
            oss << "{\n"
                << "  \"scenario\": \"" << state_.scenario_name << "\",\n"
                << "  \"seed\": " << state_.seed << ",\n"
                << "  \"strict_mode\": " << (state_.strict_mode ? "true" : "false") << ",\n"
                << "  \"avatar_pos\": [" << static_cast<int>(state_.avatar_pos.x) << ", "
                << static_cast<int>(state_.avatar_pos.y) << "],\n"
                << "  \"agent_metrics\": {\n"
                << "    \"e2e_runs\": " << state_.e2e_runs << ",\n"
                << "    \"drone_probes\": " << state_.drone_probes << ",\n"
                << "    \"repairs_attempted\": " << state_.repairs_attempted << ",\n"
                << "    \"wrong_repairs\": " << state_.healthy_gadgets_broken << ",\n"
                << "    \"collateral_induced\": " << state_.collateral_induced << ",\n"
                << "    \"session_resets\": " << state_.session_resets << "\n"
                << "  }\n"
                << "}\n";
            return oss.str();
        }

        oss << "========================================================================\n"
            << " [CYBER-VAULT 256x256 TELEMETRY STATUS]\n"
            << "========================================================================\n"
            << "  Scenario / Seed     : " << state_.scenario_name << " (seed=" << state_.seed
            << ", strict_collateral=" << (state_.strict_mode ? "ON" : "OFF") << ")\n"
            << "  Avatar 2D Position  : (" << static_cast<int>(state_.avatar_pos.x) << ", "
            << static_cast<int>(state_.avatar_pos.y) << ")\n"
            << "  Action Metrics      : " << state_.drone_probes << " drone probes | "
            << state_.e2e_runs << " E2E runs | "
            << state_.repairs_attempted << " repairs (" << state_.healthy_gadgets_broken << " wrong/blind)";
        if (state_.session_resets > 1) {
            oss << " | " << state_.session_resets << " resets";
        }
        oss << "\n";
        if (state_.oracle_hints) {
            OptimalSolutionPlan opt = compute_optimal_reference_plan();
            oss << "  Mission State       : " << (won ? "VICTORY (Reached SCADA Core at 61,224!)" : "IN PROGRESS (Path Blocked)") << "\n"
                << "  Knowledge Bracket   : k* in [" << state_.verified_prefix_lo << " .. " << state_.verified_prefix_hi << "]\n"
                << "  Bellman Optimal Ref : " << opt.total_probes << " drone probes | 0 E2E runs | "
                << opt.total_repairs << " surgical repairs (0 wrong)\n";
        }
        return oss.str();
    }

    // ========================================================================
    // 3. JSON INTERACTION TRACE & SIDE-BY-SIDE SVG MAP GENERATOR
    // ========================================================================

    bool export_json_and_svg(const std::string& json_path, const std::string& svg_path, std::string* summary_out = nullptr) {
        int cur_k_star = recompute_avatar_progress();
        bool victory = (cur_k_star == kAllCleared);
        OptimalSolutionPlan opt = compute_optimal_reference_plan();
        OptimalSolutionPlan joint_opt = compute_joint_optimal_reference_plan();

        {
            std::ofstream jout(json_path);
            if (!jout) return false;

            jout << "{\n"
                 << "  \"schema\": \"cyber_vault_256_interaction_and_optimal_trace_v3\",\n"
                 << "  \"scenario\": \"" << json_escape(state_.scenario_name) << "\",\n"
                 << "  \"seed\": " << state_.seed << ",\n"
                 << "  \"strict_mode\": " << (state_.strict_mode ? "true" : "false") << ",\n"
                 << "  \"board_dimensions\": [256, 256],\n"
                 << "  \"sectors\": 16,\n"
                 << "  \"gadgets_per_sector\": 8,\n"
                 << "  \"total_stages_D\": 128,\n"
                 << "  \"victory\": " << (victory ? "true" : "false") << ",\n";

            jout << "  \"initial_injected_faults\": [\n";
            for (size_t i = 0; i < opt.initial_fault_ks.size(); ++i) {
                int k = opt.initial_fault_ks[i];
                const auto& g = gadgets_[k];
                jout << "    { \"k\": " << k
                     << ", \"sector\": " << g.sector_i
                     << ", \"substage_m\": " << g.sub_m
                     << ", \"coord\": [" << static_cast<int>(g.pos.x) << ", " << static_cast<int>(g.pos.y) << "]"
                     << ", \"gadget_name\": \"" << json_escape(g.game_name) << "\""
                     << ", \"ssh_equivalent\": \"" << json_escape(g.ssh_equivalent) << "\" }"
                     << (i + 1 < opt.initial_fault_ks.size() ? "," : "") << "\n";
            }
            jout << "  ],\n";

            double probe_eff = (state_.drone_probes > 0)
                                   ? (static_cast<double>(opt.total_probes) / state_.drone_probes)
                                   : 0.0;
            jout << "  \"comparison_metrics\": {\n"
                 << "    \"agent\": {\n"
                 << "      \"total_interactions\": " << state_.trace_events.size() << ",\n"
                 << "      \"e2e_runs\": " << state_.e2e_runs << ",\n"
                 << "      \"drone_probes\": " << state_.drone_probes << ",\n"
                 << "      \"repairs_attempted\": " << state_.repairs_attempted << ",\n"
                 << "      \"wrong_or_blind_repairs\": " << state_.healthy_gadgets_broken << ",\n"
                 << "      \"collateral_faults_induced\": " << state_.collateral_induced << ",\n"
                 << "      \"session_resets\": " << state_.session_resets << "\n"
                 << "    },\n"
                 << "    \"bellman_optimal\": {\n"
                 << "      \"total_interactions\": " << opt.steps.size() << ",\n"
                 << "      \"drone_probes\": " << opt.total_probes << ",\n"
                 << "      \"surgical_repairs\": " << opt.total_repairs << ",\n"
                 << "      \"wrong_or_blind_repairs\": 0\n"
                 << "    },\n"
                 << "    \"joint_subspace_optimal\": {\n"
                 << "      \"total_interactions\": " << joint_opt.steps.size() << ",\n"
                 << "      \"total_probes\": " << joint_opt.total_probes << ",\n"
                 << "      \"fiber_bisection_probes\": " << (joint_opt.total_probes - static_cast<int>(joint_opt.initial_fault_ks.size()) - 1) << ",\n"
                 << "      \"e2e_symptom_checks\": " << (static_cast<int>(joint_opt.initial_fault_ks.size()) + 1) << ",\n"
                 << "      \"surgical_repairs\": " << joint_opt.total_repairs << ",\n"
                 << "      \"wrong_or_blind_repairs\": 0\n"
                 << "    },\n"
                 << "    \"probe_efficiency_ratio\": " << std::fixed << std::setprecision(4) << probe_eff << ",\n"
                 << "    \"extra_probes_over_optimal\": " << (state_.drone_probes - opt.total_probes) << "\n"
                 << "  },\n";

            jout << "  \"agent_interaction_trace\": [\n";
            for (size_t i = 0; i < state_.trace_events.size(); ++i) {
                const auto& ev = state_.trace_events[i];
                std::string g_name = (ev.target_k >= 0 && ev.target_k < kTotalGadgets)
                                         ? std::string(gadgets_[ev.target_k].game_name)
                                         : "End-to-End Board Transit";
                std::string ssh_name = (ev.target_k >= 0 && ev.target_k < kTotalGadgets)
                                           ? std::string(gadgets_[ev.target_k].ssh_equivalent)
                                           : "ssh scada-plc-unit04";
                jout << "    {\n"
                     << "      \"step\": " << ev.step_idx << ",\n"
                     << "      \"action\": \"" << ev.action_type << "\",\n"
                     << "      \"target_k\": " << ev.target_k << ",\n"
                     << "      \"from_coord\": [" << static_cast<int>(ev.from_pos.x) << ", " << static_cast<int>(ev.from_pos.y) << "],\n"
                     << "      \"to_coord\": [" << static_cast<int>(ev.to_pos.x) << ", " << static_cast<int>(ev.to_pos.y) << "],\n"
                     << "      \"gadget_name\": \"" << json_escape(g_name) << "\",\n"
                     << "      \"ssh_equivalent\": \"" << json_escape(ssh_name) << "\",\n"
                     << "      \"outcome\": \"" << json_escape(ev.outcome_code) << "\",\n"
                     << "      \"bracket_after\": [" << ev.bracket_lo << ", " << ev.bracket_hi << "],\n"
                     << "      \"true_censoring_frontier_k\": " << ev.true_frontier_k << "\n"
                     << "    }" << (i + 1 < state_.trace_events.size() ? "," : "") << "\n";
            }
            jout << "  ],\n";

            jout << "  \"bellman_optimal_trajectory\": [\n";
            for (size_t i = 0; i < opt.steps.size(); ++i) {
                const auto& st = opt.steps[i];
                const auto& g = gadgets_[st.target_k];
                jout << "    {\n"
                     << "      \"step\": " << st.step_idx << ",\n"
                     << "      \"wave\": " << st.wave_idx << ",\n"
                     << "      \"action\": \"" << st.action_type << "\",\n"
                     << "      \"target_k\": " << st.target_k << ",\n"
                     << "      \"sector\": " << g.sector_i << ",\n"
                     << "      \"substage_m\": " << g.sub_m << ",\n"
                     << "      \"from_coord\": [" << static_cast<int>(st.from_pos.x) << ", " << static_cast<int>(st.from_pos.y) << "],\n"
                     << "      \"to_coord\": [" << static_cast<int>(st.to_pos.x) << ", " << static_cast<int>(st.to_pos.y) << "],\n"
                     << "      \"gadget_name\": \"" << json_escape(g.game_name) << "\",\n"
                     << "      \"ssh_equivalent\": \"" << json_escape(g.ssh_equivalent) << "\",\n"
                     << "      \"outcome\": \"" << st.outcome_code << "\",\n"
                     << "      \"bracket_after\": [" << st.bracket_lo << ", " << st.bracket_hi << "],\n"
                     << "      \"shannon_entropy_bits\": " << std::fixed << std::setprecision(4) << st.shannon_bits << "\n"
                     << "    }" << (i + 1 < opt.steps.size() ? "," : "") << "\n";
            }
            jout << "  ]\n"
                 << "}\n";
        }

        if (!write_comparison_svg(svg_path, opt, victory)) {
            return false;
        }

        if (summary_out) {
            std::ostringstream oss;
            oss << "========================================================================\n"
                << " [SESSION TRACE & OPTIMAL COMPARISON ARTIFACTS GENERATED]\n"
                << "========================================================================\n"
                << "  1. JSON Interaction Trace : " << json_path << "\n"
                << "  2. Vector SVG Trajectory  : " << svg_path << "\n"
                << "------------------------------------------------------------------------\n"
                << "  PERFORMANCE VS. BELLMAN-OPTIMAL SOLVER:\n"
                << "    * Initial Faults (M=" << opt.initial_fault_ks.size() << ") : ";
            for (size_t i = 0; i < opt.initial_fault_ks.size(); ++i) {
                int fk = opt.initial_fault_ks[i];
                oss << "k=" << fk << " (" << static_cast<int>(gadgets_[fk].pos.x) << ","
                    << static_cast<int>(gadgets_[fk].pos.y) << ")"
                    << (i + 1 < opt.initial_fault_ks.size() ? ", " : "");
            }
            oss << "\n"
                << "    * Agent Trajectory              : " << state_.drone_probes << " probes, "
                << state_.e2e_runs << " E2E runs, " << state_.repairs_attempted << " repairs ("
                << state_.healthy_gadgets_broken << " wrong/blind)\n"
                << "    * Stage-Agnostic Optimal (Pi)   : " << opt.total_probes << " probes, 0 E2E runs, "
                << opt.total_repairs << " surgical repairs (0 wrong)\n"
                << "    * Joint Subspace (O^{-1} + Pi)  : "
                << (joint_opt.total_probes - static_cast<int>(joint_opt.initial_fault_ks.size()) - 1)
                << " fiber probes + " << (static_cast<int>(joint_opt.initial_fault_ks.size()) + 1)
                << " E2E checks (" << joint_opt.total_probes << " total), "
                << joint_opt.total_repairs << " surgical repairs (0 wrong)\n"
                << "========================================================================\n";
            *summary_out = oss.str();
        }
        return true;
    }

    static std::string cmd_help() {
        std::ostringstream oss;
        oss << "========================================================================\n"
            << " CYBER-VAULT 256: C++23 TEXT ADVENTURE CLI (16-HOP SSH ISOMORPHISM)\n"
            << "========================================================================\n"
            << " Goal: Navigate your Avatar '@' from Sector 0 (4,32) across all 16 Sectors\n"
            << "       (128 sequential rooms/gates) on the 256x256 board to the SCADA Core\n"
            << "       'X' at (61,224) in Sector 15 with ZERO blind/wrong repairs.\n\n"
            << " Commands:\n"
            << "   run                       Attempt an End-to-End Avatar transit across the\n"
            << "                             256x256 board (isomorphic to `ssh scada-plc-unit04`).\n"
            << "   probe <target>            Dispatch a controlled non-interactive drone probe\n"
            << "                             (isomorphic to `ssh -o BatchMode=yes` up to <target>).\n"
            << "   probe-mixed <target>      Dispatch a mixed-mode probe where upstream sectors\n"
            << "                             prompt interactively (`/dev/tty`) and only the target\n"
            << "                             sector enforces non-interactive mode.\n"
            << "   inspect <target>          Physically walk Avatar into room <target> to inspect\n"
            << "                             its local gadget & logs (requires all upstream\n"
            << "                             stages 0..k-1 to be operational!).\n"
            << "   repair <target>           Modify/repair the gadget in room <target>.\n"
            << "                             WARNING: Calling `repair` on a healthy room in\n"
            << "                             `--strict` mode breaks it (collateral fault)!\n"
            << "   map [0..15]               Render the 4x4 Boustrophedon board overview, or zoom\n"
            << "                             into the 64x64 ASCII map of Sector S_i (0..15).\n"
            << "   status                    Display Avatar position and action counters.\n"
            << "   export [json] [svg]       Generate the JSON interaction trace and side-by-side\n"
            << "                             Agent vs. Optimal 256x256 SVG trajectory map.\n"
            << "   quit / exit               Exit interactive shell (auto-exports JSON & SVG).\n\n"
            << " Target Formats for <target>:\n"
            << "   - Global stage index `k` in `0..127`            (e.g. `probe 63`, `repair 59`)\n"
            << "   - Sector & sub-stage `S<i>:<m>` or `S<i>_<TAG>` (e.g. `probe S7:3`, `inspect S0_K`)\n"
            << "   - Exact 2D tile coordinate `x,y`                (e.g. `probe 28,96`, `repair 10,12`)\n";
        return oss.str();
    }

private:
    std::array<std::array<TileGlyph, kGridDim>, kGridDim> grid_{};
    std::array<GadgetSpec, kTotalGadgets>                 gadgets_{};
    std::array<double, kHypothesisCnt + 1>                bellman_cost_{};
    std::array<int, kHypothesisCnt + 1>                   bellman_split_{};
    GameState                                             state_{};

    void inject_fault(int k) {
        if (k >= 0 && k < kTotalGadgets) {
            state_.gadget_healthy[k] = false;
            state_.initial_faults[k] = true;
        }
    }

    void record_trace(std::string_view action, int target_k, Coord2D from_p, Coord2D to_p,
                      std::string outcome, int true_k_star) {
        int idx = static_cast<int>(state_.trace_events.size()) + 1;
        state_.trace_events.push_back(TraceEvent{
            .step_idx        = idx,
            .action_type     = std::string(action),
            .target_k        = target_k,
            .from_pos        = from_p,
            .to_pos          = to_p,
            .outcome_code    = std::move(outcome),
            .bracket_lo      = state_.verified_prefix_lo,
            .bracket_hi      = state_.verified_prefix_hi,
            .true_frontier_k = true_k_star
        });
    }

    void carve_rect(int x0, int y0, int x1, int y1) {
        for (int y = y0; y <= y1; ++y) {
            for (int x = x0; x <= x1; ++x) {
                if (x >= 0 && x < kGridDim && y >= 0 && y < kGridDim) {
                    grid_[y][x] = TileGlyph::Floor;
                }
            }
        }
    }

    void build_world_geometry() {
        for (auto& row : grid_) {
            row.fill(TileGlyph::VoidWall);
        }

        static constexpr std::array<std::string_view, kGadgetsPerSec> kRoomDesc = {
            "North Key-Vault Entrance: Heavy electromagnetic door guarding the sector key-vault room.",
            "Locked North Key-Vault Room: Armored keypad safe inside the vault holding physical Key_i.",
            "South Power Room A: High-voltage diesel-inductor generator powering sector navigation beacons.",
            "Central Chasm Crossing: 1420mm motorized steel drawbridge spanning a subterranean cooling trench.",
            "Central Security Checkpoint: Multi-spectrum biometric laser grid verifying courier host-signatures.",
            "South Power Room B: Auxiliary relay generator supplying 48V DC interlock power to the Blast Door.",
            "East Armored Bulkhead: Main sector blast door requiring physical Key_i AND power from Generator B.",
            "Sector Boundary Airlock: Pressurized inter-sector transit tunnel connecting to the next sector."
        };

        static constexpr std::array<std::string_view, kGadgetsPerSec> kHealthyMsg = {
            "Vault Door solenoid is energized (24V OK); door swings open into the North Key-Vault Room.",
            "Safe keypad decrypted passcode cleanly in non-interactive mode; Sector Key_i collected!",
            "Beacon Generator A turbine is spinning at 3600 RPM; corridor navigation beacons are lit.",
            "Chasm Drawbridge is locked horizontal with full 1420mm clearance; safe to cross.",
            "Biometric Laser Scanner verified Ed25519 optical signature; laser barrier deactivated.",
            "Relay Generator B is online; 48V DC power is flowing to the Main Blast Door relay.",
            "Main Blast Door accepted Sector Key_i and Relay Generator B power; bulkhead retracted!",
            "Sector Exit Airlock pressure equalized; transit conduit to the next sector is open."
        };

        static constexpr std::array<std::string_view, kGadgetsPerSec> kFaultyMsg = {
            "FAULT [m=0 / SSH_AUTH_SOCK]: Vault Door control conduit is severed! Cannot enter Key-Vault Room.",
            "FAULT [m=1 / Key Passphrase]: Keypad Safe is locked waiting for interactive passphrase entry!",
            "FAULT [m=2 / UDP/53 DNS]: Beacon Generator A is shut down! Corridor beacons are completely dark.",
            "FAULT [m=3 / TCP/22 & MTU]: Chasm Drawbridge is retracted/jammed on oversized 1500mm frame!",
            "FAULT [m=4 / KEX HostKey]: Biometric Laser Grid tripped on host signature mismatch!",
            "FAULT [m=5 / sshd UseDNS]: Relay Generator B governor is hung waiting on reverse-lookup relay!",
            "FAULT [m=6 / authorized_keys]: Main Blast Door keycard slot jammed (StrictModes/ACL lock)!",
            "FAULT [m=7 / AllowTcpForwarding]: Sector Exit Airlock is mechanically sealed by bulkhead policy!"
        };

        for (int i = 0; i < kNumSectors; ++i) {
            Coord2D orig = sector_origin(i);
            carve_rect(orig.x + 4,  orig.y + 29, orig.x + 60, orig.y + 35);
            carve_rect(orig.x + 6,  orig.y + 8,  orig.x + 14, orig.y + 28);
            carve_rect(orig.x + 18, orig.y + 35, orig.x + 26, orig.y + 54);
            carve_rect(orig.x + 40, orig.y + 35, orig.x + 48, orig.y + 54);

            for (int m = 0; m < kGadgetsPerSec; ++m) {
                int k = i * kGadgetsPerSec + m;
                uint8_t gx = static_cast<uint8_t>(orig.x + kLocalOffsets[m][0]);
                uint8_t gy = static_cast<uint8_t>(orig.y + kLocalOffsets[m][1]);

                gadgets_[k] = GadgetSpec{
                    .global_k            = k,
                    .sector_i            = i,
                    .sub_m               = m,
                    .pos                 = Coord2D{gx, gy},
                    .room_min            = Coord2D{static_cast<uint8_t>(gx - 3), static_cast<uint8_t>(gy - 3)},
                    .room_max            = Coord2D{static_cast<uint8_t>(gx + 3), static_cast<uint8_t>(gy + 3)},
                    .glyph               = kSubGlyphs[m],
                    .code_tag            = kSubCodeTags[m],
                    .game_name           = kSubGameNames[m],
                    .ssh_equivalent      = kSubSshNames[m],
                    .room_description    = kRoomDesc[m],
                    .inspect_healthy_msg = kHealthyMsg[m],
                    .inspect_faulty_msg  = kFaultyMsg[m],
                    .aliased_symptom     = kSubSymptoms[m]
                };
                grid_[gy][gx] = kSubGlyphs[m];
            }
        }

        Coord2D orig15 = sector_origin(15);
        grid_[orig15.y + 32][orig15.x + 61] = TileGlyph::ScadaCoreX;
    }

    void compute_bellman_table() {
        bellman_cost_[0]  = 0.0;
        bellman_cost_[1]  = 0.0;
        bellman_split_[0] = 0;
        bellman_split_[1] = 0;
        for (int w = 2; w <= kHypothesisCnt; ++w) {
            double best = 1e18;
            int best_l  = 1;
            for (int l = 1; l < w; ++l) {
                int r = w - l;
                double cost = 1.0 + (static_cast<double>(l) / w) * bellman_cost_[l]
                                  + (static_cast<double>(r) / w) * bellman_cost_[r];
                if (cost < best - 1e-12) {
                    best   = cost;
                    best_l = l;
                }
            }
            bellman_cost_[w]  = best;
            bellman_split_[w] = best_l;
        }
    }

    int recompute_avatar_progress() {
        state_.keys_held_mask = 0;
        for (int k = 0; k < kTotalGadgets; ++k) {
            if (!state_.gadget_healthy[k]) {
                state_.avatar_max_reached_k = k;
                return k;
            }
            if ((k % kGadgetsPerSec) == 1) {
                int sec = k / kGadgetsPerSec;
                state_.keys_held_mask |= static_cast<uint16_t>(1U << sec);
            }
        }
        Coord2D orig15 = sector_origin(15);
        state_.avatar_pos = Coord2D{
            static_cast<uint8_t>(orig15.x + 61),
            static_cast<uint8_t>(orig15.y + 32)
        };
        state_.avatar_max_reached_k = kAllCleared;
        return kAllCleared;
    }

    bool write_comparison_svg(const std::string& svg_path, const OptimalSolutionPlan& opt, bool victory) const {
        std::ofstream out(svg_path);
        if (!out) return false;

        constexpr double kScale = 2.25;
        constexpr double kBoardPx = kGridDim * kScale; // 576
        constexpr double kLeftX = 50.0;
        constexpr double kRightX = 710.0;
        constexpr double kBoardY = 115.0;

        out << std::fixed << std::setprecision(1);
        out << "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 1340 860\" width=\"100%\" height=\"100%\">\n"
            << "<defs>\n"
            << "  <linearGradient id=\"bgGrad\" x1=\"0\" y1=\"0\" x2=\"1\" y2=\"1\">\n"
            << "    <stop offset=\"0%\" stop-color=\"#0f172a\"/>\n"
            << "    <stop offset=\"100%\" stop-color=\"#1e293b\"/>\n"
            << "  </linearGradient>\n"
            << "  <marker id=\"arrowPass\" viewBox=\"0 0 10 10\" refX=\"7\" refY=\"5\" markerWidth=\"5\" markerHeight=\"5\" orient=\"auto-start-reverse\">\n"
            << "    <path d=\"M 0 1 L 10 5 L 0 9 z\" fill=\"#38bdf8\"/>\n"
            << "  </marker>\n"
            << "  <marker id=\"arrowBlock\" viewBox=\"0 0 10 10\" refX=\"7\" refY=\"5\" markerWidth=\"5\" markerHeight=\"5\" orient=\"auto-start-reverse\">\n"
            << "    <path d=\"M 0 1 L 10 5 L 0 9 z\" fill=\"#f43f5e\"/>\n"
            << "  </marker>\n"
            << "  <marker id=\"arrowOpt\" viewBox=\"0 0 10 10\" refX=\"7\" refY=\"5\" markerWidth=\"5\" markerHeight=\"5\" orient=\"auto-start-reverse\">\n"
            << "    <path d=\"M 0 1 L 10 5 L 0 9 z\" fill=\"#10b981\"/>\n"
            << "  </marker>\n"
            << "</defs>\n";

        out << "<rect width=\"1340\" height=\"860\" fill=\"url(#bgGrad)\"/>\n";

        out << "<rect x=\"30\" y=\"18\" width=\"1280\" height=\"76\" rx=\"10\" fill=\"#090d16\" stroke=\"#334155\" stroke-width=\"1.5\"/>\n"
            << "<text x=\"670\" y=\"46\" font-family=\"monospace\" font-size=\"18\" font-weight=\"bold\" fill=\"#f8fafc\" text-anchor=\"middle\">"
            << "CYBER-VAULT 256x256: AGENT TRAJECTORY vs. BELLMAN-OPTIMAL SOLUTION (Scenario: "
            << state_.scenario_name << " | Seed: " << state_.seed << ")</text>\n"
            << "<text x=\"670\" y=\"74\" font-family=\"monospace\" font-size=\"13\" fill=\"#94a3b8\" text-anchor=\"middle\">"
            << "Agent: " << state_.drone_probes << " Probes, " << state_.e2e_runs << " E2E Runs, "
            << state_.repairs_attempted << " Repairs (" << state_.healthy_gadgets_broken << " Wrong) | "
            << "Bellman Optimal: " << opt.total_probes << " Probes, " << opt.total_repairs
            << " Surgical Repairs (0 Wrong) | Status: " << (victory ? "SOLVED" : "INCOMPLETE") << "</text>\n";

        auto render_board_base = [&](double ox, double oy, std::string_view title, std::string_view subtitle, std::string_view border_col) {
            out << "<text x=\"" << (ox + kBoardPx / 2.0) << "\" y=\"" << (oy - 8.0)
                << "\" font-family=\"monospace\" font-size=\"14\" font-weight=\"bold\" fill=\"" << border_col
                << "\" text-anchor=\"middle\">" << title << "</text>\n";

            out << "<rect x=\"" << ox << "\" y=\"" << oy << "\" width=\"" << kBoardPx
                << "\" height=\"" << kBoardPx << "\" fill=\"#090d16\" stroke=\"" << border_col << "\" stroke-width=\"2\"/>\n";

            for (int i = 0; i < kNumSectors; ++i) {
                Coord2D s_orig = sector_origin(i);
                double sx = ox + s_orig.x * kScale;
                double sy = oy + s_orig.y * kScale;
                double s_dim = kSectorSize * kScale;

                out << "<rect x=\"" << sx << "\" y=\"" << sy << "\" width=\"" << s_dim
                    << "\" height=\"" << s_dim << "\" fill=\"none\" stroke=\"#1e293b\" stroke-width=\"1\"/>\n";
                out << "<text x=\"" << (sx + 5.0) << "\" y=\"" << (sy + 13.0)
                    << "\" font-family=\"monospace\" font-size=\"10\" fill=\"#475569\">S" << i
                    << " (" << kSectorHostnames[i] << ")</text>\n";

                out << "<rect x=\"" << (ox + (s_orig.x + 4) * kScale) << "\" y=\"" << (oy + (s_orig.y + 29) * kScale)
                    << "\" width=\"" << (56 * kScale) << "\" height=\"" << (6 * kScale)
                    << "\" fill=\"#1e293b\" opacity=\"0.75\"/>\n";
                out << "<rect x=\"" << (ox + (s_orig.x + 6) * kScale) << "\" y=\"" << (oy + (s_orig.y + 8) * kScale)
                    << "\" width=\"" << (8 * kScale) << "\" height=\"" << (20 * kScale)
                    << "\" fill=\"#1e293b\" opacity=\"0.75\"/>\n";
                out << "<rect x=\"" << (ox + (s_orig.x + 18) * kScale) << "\" y=\"" << (oy + (s_orig.y + 35) * kScale)
                    << "\" width=\"" << (8 * kScale) << "\" height=\"" << (19 * kScale)
                    << "\" fill=\"#1e293b\" opacity=\"0.75\"/>\n";
                out << "<rect x=\"" << (ox + (s_orig.x + 40) * kScale) << "\" y=\"" << (oy + (s_orig.y + 35) * kScale)
                    << "\" width=\"" << (8 * kScale) << "\" height=\"" << (19 * kScale)
                    << "\" fill=\"#1e293b\" opacity=\"0.75\"/>\n";
            }

            out << "<polyline fill=\"none\" stroke=\"#334155\" stroke-width=\"1.5\" stroke-dasharray=\"4,4\" points=\"";
            for (int k = 0; k < kTotalGadgets; ++k) {
                double gx = ox + gadgets_[k].pos.x * kScale;
                double gy = oy + gadgets_[k].pos.y * kScale;
                out << gx << "," << gy << " ";
            }
            out << "\"/>\n";

            for (int k = 0; k < kTotalGadgets; ++k) {
                const auto& g = gadgets_[k];
                double gx = ox + g.pos.x * kScale;
                double gy = oy + g.pos.y * kScale;
                bool init_fault = state_.initial_faults[k];
                if (init_fault) {
                    out << "<circle cx=\"" << gx << "\" cy=\"" << gy << "\" r=\"5.5\" fill=\"#ef4444\" stroke=\"#fef2f2\" stroke-width=\"1.2\"/>\n";
                } else {
                    out << "<circle cx=\"" << gx << "\" cy=\"" << gy << "\" r=\"2.4\" fill=\"#64748b\"/>\n";
                }
            }

            double start_x = ox + 4 * kScale;
            double start_y = oy + 32 * kScale;
            Coord2D orig15 = sector_origin(15);
            double core_x = ox + (orig15.x + 61) * kScale;
            double core_y = oy + (orig15.y + 32) * kScale;

            out << "<circle cx=\"" << start_x << "\" cy=\"" << start_y << "\" r=\"6\" fill=\"#38bdf8\" stroke=\"#ffffff\" stroke-width=\"1.5\"/>\n"
                << "<text x=\"" << (start_x + 8) << "\" y=\"" << (start_y + 4) << "\" font-family=\"monospace\" font-size=\"10\" font-weight=\"bold\" fill=\"#38bdf8\">START(4,32)</text>\n";
            out << "<rect x=\"" << (core_x - 6) << "\" y=\"" << (core_y - 6) << "\" width=\"12\" height=\"12\" fill=\"#eab308\" stroke=\"#ffffff\" stroke-width=\"1.5\"/>\n"
                << "<text x=\"" << (core_x - 32) << "\" y=\"" << (core_y - 10) << "\" font-family=\"monospace\" font-size=\"10\" font-weight=\"bold\" fill=\"#eab308\">CORE(61,224)</text>\n";

            out << "<text x=\"" << (ox + kBoardPx / 2.0) << "\" y=\"" << (oy + kBoardPx + 20.0)
                << "\" font-family=\"monospace\" font-size=\"12\" fill=\"#cbd5e1\" text-anchor=\"middle\">"
                << subtitle << "</text>\n";
        };

        std::string left_sub = "Agent Actions: " + std::to_string(state_.trace_events.size()) +
                               " | Probes: " + std::to_string(state_.drone_probes) +
                               " | Repairs: " + std::to_string(state_.repairs_attempted) +
                               " (" + std::to_string(state_.healthy_gadgets_broken) + " Wrong)";
        render_board_base(kLeftX, kBoardY,
                          "LEFT: AGENT INTERACTIVE TRAJECTORY (Actual Path &amp; Probes)",
                          left_sub, "#38bdf8");

        for (const auto& ev : state_.trace_events) {
            double x1 = kLeftX + ev.from_pos.x * kScale;
            double y1 = kBoardY + ev.from_pos.y * kScale;
            double x2 = kLeftX + ev.to_pos.x * kScale;
            double y2 = kBoardY + ev.to_pos.y * kScale;

            if (ev.action_type == "PROBE" || ev.action_type == "PROBE_MIXED" || ev.action_type == "INSPECT") {
                bool passed = (ev.outcome_code.find("PASS_1") != std::string::npos ||
                               ev.outcome_code == "INSPECT_HEALTHY");
                std::string col = passed ? "#38bdf8" : "#f43f5e";
                std::string marker = passed ? "url(#arrowPass)" : "url(#arrowBlock)";
                out << "<line x1=\"" << x1 << "\" y1=\"" << y1 << "\" x2=\"" << x2 << "\" y2=\"" << y2
                    << "\" stroke=\"" << col << "\" stroke-width=\"1.6\" opacity=\"0.85\" marker-end=\"" << marker << "\"/>\n";
                out << "<circle cx=\"" << x2 << "\" cy=\"" << y2 << "\" r=\"3.8\" fill=\"" << col << "\"/>\n";
                out << "<text x=\"" << (x2 + 5) << "\" y=\"" << (y2 - 4)
                    << "\" font-family=\"monospace\" font-size=\"9\" fill=\"" << col << "\">#" << ev.step_idx << "</text>\n";
            } else if (ev.action_type == "REPAIR") {
                bool ok = (ev.outcome_code == "SURGICAL_REPAIR_SUCCESS");
                std::string col = ok ? "#22c55e" : "#eab308";
                out << "<circle cx=\"" << x2 << "\" cy=\"" << y2 << "\" r=\"8.0\" fill=\"none\" stroke=\""
                    << col << "\" stroke-width=\"2.5\"/>\n";
                out << "<text x=\"" << (x2 - 18) << "\" y=\"" << (y2 + 15)
                    << "\" font-family=\"monospace\" font-size=\"10\" font-weight=\"bold\" fill=\"" << col
                    << "\">FIX#" << ev.step_idx << "(k=" << ev.target_k << ")</text>\n";
            } else if (ev.action_type == "RUN_E2E") {
                out << "<line x1=\"" << x1 << "\" y1=\"" << y1 << "\" x2=\"" << x2 << "\" y2=\"" << y2
                    << "\" stroke=\"#a855f7\" stroke-width=\"1.4\" stroke-dasharray=\"3,3\" opacity=\"0.8\"/>\n";
            }
        }

        std::string right_sub = "Optimal Steps: " + std::to_string(opt.steps.size()) +
                                " | Probes: " + std::to_string(opt.total_probes) +
                                " | Surgical Repairs: " + std::to_string(opt.total_repairs) + " (0 Wrong)";
        render_board_base(kRightX, kBoardY,
                          "RIGHT: EXACT BELLMAN-OPTIMAL SOLUTION (Prefix Bisection DP)",
                          right_sub, "#10b981");

        for (const auto& st : opt.steps) {
            double x1 = kRightX + st.from_pos.x * kScale;
            double y1 = kBoardY + st.from_pos.y * kScale;
            double x2 = kRightX + st.to_pos.x * kScale;
            double y2 = kBoardY + st.to_pos.y * kScale;

            if (st.action_type == "OPT_PROBE") {
                bool passed = (st.outcome_code.find("PASS_1") != std::string::npos);
                std::string col = passed ? "#10b981" : "#f59e0b";
                out << "<line x1=\"" << x1 << "\" y1=\"" << y1 << "\" x2=\"" << x2 << "\" y2=\"" << y2
                    << "\" stroke=\"" << col << "\" stroke-width=\"1.6\" opacity=\"0.85\" marker-end=\"url(#arrowOpt)\"/>\n";
                out << "<circle cx=\"" << x2 << "\" cy=\"" << y2 << "\" r=\"3.5\" fill=\"" << col << "\"/>\n";
                out << "<text x=\"" << (x2 + 5) << "\" y=\"" << (y2 - 4)
                    << "\" font-family=\"monospace\" font-size=\"9\" fill=\"" << col << "\">" << st.step_idx << "</text>\n";
            } else if (st.action_type == "OPT_REPAIR") {
                out << "<circle cx=\"" << x2 << "\" cy=\"" << y2 << "\" r=\"8.5\" fill=\"none\" stroke=\"#22c55e\" stroke-width=\"2.6\"/>\n";
                out << "<text x=\"" << (x2 - 22) << "\" y=\"" << (y2 + 15)
                    << "\" font-family=\"monospace\" font-size=\"10\" font-weight=\"bold\" fill=\"#22c55e\">OPT_FIX(k="
                    << st.target_k << ")</text>\n";
            }
        }

        out << "<rect x=\"30\" y=\"730\" width=\"1280\" height=\"110\" rx=\"8\" fill=\"#090d16\" stroke=\"#334155\" stroke-width=\"1.5\"/>\n"
            << "<text x=\"50\" y=\"754\" font-family=\"monospace\" font-size=\"13\" font-weight=\"bold\" fill=\"#f8fafc\">"
            << "LEGEND &amp; FORMAL EQUIVALENCE SUMMARY (2D Dungeon Game  &lt;===&gt;  16-Hop Cascaded SSH Transducer):</text>\n"
            << "<circle cx=\"60\" cy=\"776\" r=\"5.5\" fill=\"#ef4444\" stroke=\"#fef2f2\" stroke-width=\"1.2\"/>\n"
            << "<text x=\"74\" y=\"780\" font-family=\"monospace\" font-size=\"12\" fill=\"#cbd5e1\">Injected Faults (k*)</text>\n"
            << "<circle cx=\"250\" cy=\"776\" r=\"4\" fill=\"#38bdf8\"/>\n"
            << "<text x=\"264\" y=\"780\" font-family=\"monospace\" font-size=\"12\" fill=\"#cbd5e1\">Drone Probe PASS (Bit=1)</text>\n"
            << "<circle cx=\"470\" cy=\"776\" r=\"4\" fill=\"#f43f5e\"/>\n"
            << "<text x=\"484\" y=\"780\" font-family=\"monospace\" font-size=\"12\" fill=\"#cbd5e1\">Drone Probe BLOCKED (Bit=0)</text>\n"
            << "<circle cx=\"720\" cy=\"776\" r=\"7\" fill=\"none\" stroke=\"#22c55e\" stroke-width=\"2.2\"/>\n"
            << "<text x=\"736\" y=\"780\" font-family=\"monospace\" font-size=\"12\" fill=\"#cbd5e1\">Surgical Frontier Repair</text>\n"
            << "<circle cx=\"950\" cy=\"776\" r=\"7\" fill=\"none\" stroke=\"#eab308\" stroke-width=\"2.2\"/>\n"
            << "<text x=\"966\" y=\"780\" font-family=\"monospace\" font-size=\"12\" fill=\"#cbd5e1\">Blind/Wrong Repair Attempt</text>\n";

        std::ostringstream fault_line;
        fault_line << "True Fault Chain (M=" << opt.initial_fault_ks.size() << "): ";
        for (size_t i = 0; i < opt.initial_fault_ks.size(); ++i) {
            int fk = opt.initial_fault_ks[i];
            const auto& g = gadgets_[fk];
            fault_line << "[Wave " << (i + 1) << "] k=" << fk << " S" << g.sector_i << ":" << g.sub_m
                       << " @(" << static_cast<int>(g.pos.x) << "," << static_cast<int>(g.pos.y) << ") "
                       << g.code_tag << "  ";
        }
        out << "<text x=\"50\" y=\"808\" font-family=\"monospace\" font-size=\"12\" fill=\"#38bdf8\">"
            << fault_line.str() << "</text>\n";

        out << "<text x=\"50\" y=\"828\" font-family=\"monospace\" font-size=\"12\" fill=\"#10b981\">"
            << "Bellman-Optimal Complexity: O(M log2 D) = " << opt.total_probes
            << " prefix probes + " << opt.total_repairs
            << " surgical repairs (Shannon Lower Bound: 7.0112 bits/fault vs. 7.0155 avg probes).</text>\n";

        out << "</svg>\n";
        return true;
    }
};

// ============================================================================
// 4. COMMAND DISPATCHER & LOCAL HTTP DAEMON (ZERO-INSPECTION ISOLATION)
// ============================================================================

inline std::vector<std::string> tokenize_line(std::string_view line) {
    std::vector<std::string> tokens;
    std::istringstream iss{std::string(line)};
    std::string tok;
    while (iss >> tok) {
        tokens.push_back(tok);
    }
    return tokens;
}

inline std::string url_decode(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (size_t i = 0; i < sv.size(); ++i) {
        if (sv[i] == '+') {
            out.push_back(' ');
        } else if (sv[i] == '%' && i + 2 < sv.size()) {
            std::string hex{sv.substr(i + 1, 2)};
            char* endp = nullptr;
            long val = std::strtol(hex.c_str(), &endp, 16);
            if (endp && *endp == '\0') {
                out.push_back(static_cast<char>(val));
                i += 2;
            } else {
                out.push_back(sv[i]);
            }
        } else {
            out.push_back(sv[i]);
        }
    }
    return out;
}

inline std::optional<std::string> get_query_param(std::string_view query, std::string_view key) {
    size_t pos = 0;
    while (pos < query.size()) {
        size_t amp = query.find('&', pos);
        std::string_view pair = (amp == std::string_view::npos)
                                    ? query.substr(pos)
                                    : query.substr(pos, amp - pos);
        size_t eq = pair.find('=');
        if (eq != std::string_view::npos && pair.substr(0, eq) == key) {
            return url_decode(pair.substr(eq + 1));
        }
        if (amp == std::string_view::npos) break;
        pos = amp + 1;
    }
    return std::nullopt;
}

inline std::string read_file_contents(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return {};
    std::ostringstream oss;
    oss << in.rdbuf();
    return oss.str();
}

} // namespace cyber_vault

int main(int argc, char* argv[]) {
    using namespace cyber_vault;

    CyberVaultEngine engine;
    std::string state_file;
    std::string json_out_path = "agent_session_trace.json";
    std::string svg_out_path  = "agent_vs_optimal_map.svg";
    std::string scenario      = "adversarial5";
    uint32_t seed             = 20261025;
    bool strict_mode          = false;
    bool oracle_hints         = false;
    bool json_mode            = false;
    bool has_init_flag        = false;
    bool disallow_resets      = false;
    int  serve_port           = 0;
    std::vector<std::string> one_shot_cmd;

    for (int i = 1; i < argc; ++i) {
        std::string_view arg(argv[i]);
        if (arg == "--state" && i + 1 < argc) {
            state_file = argv[++i];
        } else if (arg == "--trace-json" && i + 1 < argc) {
            json_out_path = argv[++i];
        } else if (arg == "--trace-svg" && i + 1 < argc) {
            svg_out_path = argv[++i];
        } else if (arg == "--scenario" && i + 1 < argc) {
            scenario = argv[++i];
            has_init_flag = true;
        } else if (arg == "--seed" && i + 1 < argc) {
            seed = static_cast<uint32_t>(std::stoul(argv[++i]));
            has_init_flag = true;
        } else if (arg == "--serve" && i + 1 < argc) {
            serve_port = std::stoi(argv[++i]);
        } else if (arg == "--no-reset") {
            disallow_resets = true;
        } else if (arg == "--strict") {
            strict_mode = true;
        } else if (arg == "--oracle-hints") {
            oracle_hints = true;
        } else if (arg == "--json") {
            json_mode = true;
        } else if (arg == "--init") {
            has_init_flag = true;
        } else if (arg == "--cmd" && i + 1 < argc) {
            one_shot_cmd = tokenize_line(argv[++i]);
        } else if (arg == "--help" || arg == "-h") {
            std::cout << CyberVaultEngine::cmd_help();
            return 0;
        } else {
            one_shot_cmd.emplace_back(arg);
        }
    }

    if (!state_file.empty()) {
        bool loaded = engine.load_from_file(state_file);
        if (has_init_flag || !loaded) {
            if (loaded && has_init_flag) {
                engine.increment_resets();
            }
            engine.load_scenario(scenario, seed, strict_mode, oracle_hints);
            engine.increment_resets();
            engine.save_to_file(state_file);
        }
    } else {
        engine.load_scenario(scenario, seed, strict_mode, oracle_hints);
        engine.increment_resets();
    }

    auto dispatch_command_str = [&](const std::vector<std::string>& toks, bool use_json, bool* should_quit = nullptr) -> std::string {
        if (should_quit) *should_quit = false;
        if (toks.empty()) return "";
        std::string cmd = toks[0];
        std::transform(cmd.begin(), cmd.end(), cmd.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        std::string out;
        if (cmd == "quit" || cmd == "exit" || cmd == "q") {
            if (should_quit) *should_quit = true;
            return "Session closed.\n";
        } else if (cmd == "help" || cmd == "?") {
            out = CyberVaultEngine::cmd_help();
        } else if (cmd == "run" || cmd == "e2e") {
            out = engine.cmd_run_e2e(use_json);
        } else if (cmd == "probe" || cmd == "drone" || cmd == "bisect") {
            if (toks.size() < 2) {
                out = "Usage: probe <k | S_i:m | x,y> (e.g., `probe 63`, `probe S7:3`, `probe 28,96`)\n";
            } else if (auto k = engine.parse_gadget_target(toks[1])) {
                out = engine.cmd_drone_probe(*k, use_json);
            } else {
                out = "Error: Invalid target '" + toks[1] + "'. Use k in 0..127, S0:0..S15:7, or x,y.\n";
            }
        } else if (cmd == "probe-mixed" || cmd == "mixed") {
            if (toks.size() < 2) {
                out = "Usage: probe-mixed <k | S_i:m | x,y>\n";
            } else if (auto k = engine.parse_gadget_target(toks[1])) {
                out = engine.cmd_mixed_mode_probe(*k, use_json);
            } else {
                out = "Error: Invalid target '" + toks[1] + "'.\n";
            }
        } else if (cmd == "inspect" || cmd == "enter" || cmd == "walk" || cmd == "look") {
            if (toks.size() < 2) {
                out = "Usage: inspect <k | S_i:m | x,y> (e.g., `inspect 1`, `inspect S0:1`, `inspect 10,12`)\n";
            } else if (auto k = engine.parse_gadget_target(toks[1])) {
                out = engine.cmd_inspect_room(*k, use_json);
            } else {
                out = "Error: Invalid target '" + toks[1] + "'.\n";
            }
        } else if (cmd == "repair" || cmd == "fix" || cmd == "unlock") {
            if (toks.size() < 2) {
                out = "Usage: repair <k | S_i:m | x,y> (e.g., `repair 1`, `repair S0:1`, `repair 10,12`)\n";
            } else if (auto k = engine.parse_gadget_target(toks[1])) {
                out = engine.cmd_repair_gadget(*k, use_json);
            } else {
                out = "Error: Invalid target '" + toks[1] + "'.\n";
            }
        } else if (cmd == "map" || cmd == "board") {
            if (toks.size() >= 2) {
                try {
                    int sec = std::stoi(toks[1]);
                    out = engine.cmd_render_map(sec);
                } catch (...) {
                    out = "Usage: map [0..15]\n";
                }
            } else {
                out = engine.cmd_render_map(std::nullopt);
            }
        } else if (cmd == "hint" || cmd == "bellman" || cmd == "advisor") {
            if (serve_port > 0 && !oracle_hints) {
                out = "Error: `hint` is disabled on this production incident server.\n";
            } else {
                out = engine.cmd_bellman_hint(use_json);
            }
        } else if (cmd == "solve" || cmd == "autosolve") {
            if (serve_port > 0 && !oracle_hints) {
                out = "Error: `solve` is disabled on this production incident server.\n";
            } else {
                out = engine.cmd_autosolve(use_json);
            }
        } else if (cmd == "export" || cmd == "report" || cmd == "trace") {
            std::string jp = (toks.size() >= 2 && serve_port == 0) ? toks[1] : json_out_path;
            std::string sp = (toks.size() >= 3 && serve_port == 0) ? toks[2] : svg_out_path;
            std::string summary;
            if (engine.export_json_and_svg(jp, sp, &summary)) {
                if (use_json) {
                    out = "{ \"action\": \"export\", \"json_trace\": \"" + jp +
                          "\", \"svg_map\": \"" + sp + "\" }\n";
                } else {
                    out = summary;
                }
            } else {
                out = "Error: Failed to write export files.\n";
            }
        } else if (cmd == "status" || cmd == "stat" || cmd == "inventory") {
            out = engine.cmd_status(use_json);
        } else if (cmd == "reset" || cmd == "init") {
            if (disallow_resets) {
                engine.increment_resets();
                out = "CHANGE-CONTROL POLICY VIOLATION: Universe resets (`reset`/`init`) are disabled on this server! "
                      "Attempt logged in audit trace.\n";
            } else {
                std::string preset = (toks.size() >= 2) ? toks[1] : scenario;
                uint32_t new_seed  = (toks.size() >= 3) ? static_cast<uint32_t>(std::stoul(toks[2])) : seed;
                engine.load_scenario(preset, new_seed, strict_mode, oracle_hints);
                engine.increment_resets();
                out = engine.cmd_status(use_json);
            }
        } else {
            out = "Unknown command '" + cmd + "'. Type `help` for available commands.\n";
        }

        if (!state_file.empty()) {
            engine.save_to_file(state_file);
        }
        // Always keep trace & SVG updated on disk in server mode
        if (serve_port > 0) {
            engine.export_json_and_svg(json_out_path, svg_out_path, nullptr);
        }
        return out;
    };

    // ========================================================================
    // HTTP SERVER MODE (`--serve <port>`)
    // Runs locally so the LLM agent interacts strictly via `curl` over HTTP
    // and has ZERO access to the binary, source code, or `.state` file!
    // ========================================================================
    if (serve_port > 0) {
        int server_fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) {
            std::cerr << "Error: Failed to create socket.\n";
            return 1;
        }
        int opt = 1;
        ::setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1
        addr.sin_port        = htons(static_cast<uint16_t>(serve_port));

        if (::bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            std::cerr << "Error: Failed to bind to 127.0.0.1:" << serve_port << "\n";
            ::close(server_fd);
            return 1;
        }
        if (::listen(server_fd, 16) < 0) {
            std::cerr << "Error: Failed to listen on socket.\n";
            ::close(server_fd);
            return 1;
        }

        engine.export_json_and_svg(json_out_path, svg_out_path, nullptr);
        std::cout << "========================================================================\n"
                  << " CYBER-VAULT 256 HTTP DAEMON LISTENING ON http://127.0.0.1:" << serve_port << "\n"
                  << "========================================================================\n"
                  << "  Scenario / Seed   : " << scenario << " (seed=" << seed << ")\n"
                  << "  Strict Collateral : " << (strict_mode ? "ENABLED" : "DISABLED") << "\n"
                  << "  No-Reset Policy   : " << (disallow_resets ? "ENFORCED" : "DISABLED") << "\n"
                  << "  Live JSON Trace   : " << json_out_path << "\n"
                  << "  Live SVG Map      : " << svg_out_path << "\n"
                  << "  Endpoints:\n"
                  << "    GET  http://127.0.0.1:" << serve_port << "/cmd?c=probe+63\n"
                  << "    POST http://127.0.0.1:" << serve_port << "/cmd   (body: `probe 63`)\n"
                  << "    GET  http://127.0.0.1:" << serve_port << "/trace.json\n"
                  << "    GET  http://127.0.0.1:" << serve_port << "/map.svg\n"
                  << "========================================================================\n" << std::flush;

        while (true) {
            sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);
            int client_fd = ::accept(server_fd, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
            if (client_fd < 0) continue;

            std::string req;
            char buf[4096];
            ssize_t n = ::read(client_fd, buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                req.assign(buf, static_cast<size_t>(n));
            }

            // Parse first request line: METHOD /path?query HTTP/1.1
            std::istringstream rstream(req);
            std::string method, full_target, http_ver;
            rstream >> method >> full_target >> http_ver;

            std::string path = full_target;
            std::string query;
            auto qpos = full_target.find('?');
            if (qpos != std::string::npos) {
                path  = full_target.substr(0, qpos);
                query = full_target.substr(qpos + 1);
            }

            // Extract HTTP request body (for POST)
            std::string req_body;
            auto header_end = req.find("\r\n\r\n");
            if (header_end != std::string::npos) {
                req_body = req.substr(header_end + 4);
            }

            bool req_json = json_mode;
            if (auto fmt = get_query_param(query, "format")) {
                if (*fmt == "json") req_json = true;
            }

            std::string content_type = req_json ? "application/json; charset=utf-8"
                                                : "text/plain; charset=utf-8";
            std::string resp_body;

            if (path == "/trace.json") {
                engine.export_json_and_svg(json_out_path, svg_out_path, nullptr);
                content_type = "application/json; charset=utf-8";
                resp_body = read_file_contents(json_out_path);
            } else if (path == "/map.svg") {
                engine.export_json_and_svg(json_out_path, svg_out_path, nullptr);
                content_type = "image/svg+xml; charset=utf-8";
                resp_body = read_file_contents(svg_out_path);
            } else {
                // Determine command string from query `?c=...`, `?cmd=...`, POST body, or URL path
                std::string cmd_line;
                if (auto c_param = get_query_param(query, "c")) {
                    cmd_line = *c_param;
                } else if (auto cmd_param = get_query_param(query, "cmd")) {
                    cmd_line = *cmd_param;
                } else if (!req_body.empty()) {
                    cmd_line = req_body;
                } else if (path.size() > 1 && path != "/cmd") {
                    std::string p_clean = path.substr(1);
                    std::replace(p_clean.begin(), p_clean.end(), '/', ' ');
                    cmd_line = url_decode(p_clean);
                } else {
                    cmd_line = "status";
                }

                auto toks = tokenize_line(cmd_line);
                std::cout << "[HTTP] " << method << " " << full_target << " -> cmd: `";
                for (size_t i = 0; i < toks.size(); ++i) {
                    std::cout << toks[i] << (i + 1 < toks.size() ? " " : "");
                }
                std::cout << "`\n" << std::flush;

                resp_body = dispatch_command_str(toks, req_json);
            }

            std::ostringstream http_resp;
            http_resp << "HTTP/1.1 200 OK\r\n"
                      << "Content-Type: " << content_type << "\r\n"
                      << "Content-Length: " << resp_body.size() << "\r\n"
                      << "Connection: close\r\n\r\n"
                      << resp_body;
            std::string wire = http_resp.str();
            (void)::write(client_fd, wire.data(), wire.size());
            ::close(client_fd);
        }
        ::close(server_fd);
        return 0;
    }

    if (!one_shot_cmd.empty()) {
        std::cout << dispatch_command_str(one_shot_cmd, json_mode);
        return 0;
    }

    if (!json_mode) {
        std::cout << "========================================================================\n"
                  << " WELCOME TO CYBER-VAULT 256 (C++23 Interactive 2D Diagnostic Adventure)\n"
                  << " Isomorphic 256x256 Board Representation of the 16-Hop Cascaded SSH Chain\n"
                  << " Type `help` for commands, `run` for E2E alarm, `probe` for prefix tests.\n"
                  << "========================================================================\n";
        std::cout << engine.cmd_status(false);
    }

    std::string line;
    while (true) {
        if (!json_mode) {
            std::cout << "\ncyber-vault-256> " << std::flush;
        }
        if (!std::getline(std::cin, line)) {
            break;
        }
        auto toks = tokenize_line(line);
        bool quit_now = false;
        std::string out = dispatch_command_str(toks, json_mode, &quit_now);
        std::cout << out;
        if (quit_now) {
            break;
        }
    }

    std::string end_summary;
    if (engine.export_json_and_svg(json_out_path, svg_out_path, &end_summary) && !json_mode) {
        std::cout << "\n" << end_summary;
    }

    return 0;
}
