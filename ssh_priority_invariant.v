(* ==============================================================================
 * ssh_priority_invariant.v
 *
 * Mechanized Formal Verification of Kami / GAA Causal Priority Invariant
 * in the Rocq / Coq Interactive Theorem Prover.
 *
 * Proves that in any reachable state of the SSH Diagnoser & Solver GAA
 * system, the Tier 2 SSH configuration fix (ActApplySSHFix) CANNOT execute
 * while Tier 1 storage exhaustion (st_enospc = true) is active.
 *
 * Mechanically closed with Qed. Zero axioms. Zero Admitted.
 * ============================================================================== *)

Inductive Phase : Set :=
  | PhaseProbeSystem   : Phase
  | PhaseProbePK       : Phase
  | PhaseSolveCritical : Phase
  | PhaseSolveConfig   : Phase
  | PhaseDone          : Phase.

Inductive Action : Set :=
  | ActNone        : Action
  | ActCheckStorage: Action
  | ActPurgeTmp    : Action
  | ActApplySSHFix : Action.

Record State : Set := mkState {
  st_enospc        : bool;
  st_strict_modes  : bool;
  st_phase         : Phase;
  st_action        : Action
}.

Definition is_initial (s : State) : Prop :=
  st_phase s = PhaseProbeSystem /\ st_action s = ActNone.

Inductive step : State -> State -> Prop :=
  | StepProbeSystem (s : State) :
      st_phase s = PhaseProbeSystem ->
      step s (mkState (st_enospc s) (st_strict_modes s) PhaseProbePK ActNone)

  | StepProbePKCritical (s : State) :
      st_phase s = PhaseProbePK ->
      st_enospc s = true ->
      step s (mkState (st_enospc s) (st_strict_modes s) PhaseSolveCritical ActNone)

  | StepProbePKNormal (s : State) :
      st_phase s = PhaseProbePK ->
      st_enospc s = false ->
      step s (mkState (st_enospc s) (st_strict_modes s) PhaseSolveConfig ActNone)

  | StepSolveCritical (s : State) :
      st_phase s = PhaseSolveCritical ->
      st_enospc s = true ->
      st_action s = ActNone ->
      step s (mkState (st_enospc s) (st_strict_modes s) PhaseSolveCritical ActPurgeTmp)

  | StepAckCritical (s : State) :
      st_phase s = PhaseSolveCritical ->
      st_action s = ActPurgeTmp ->
      (* Storage Headroom Restored: st_enospc becomes false *)
      step s (mkState false (st_strict_modes s) PhaseSolveConfig ActNone)

  | StepSolveConfig (s : State) :
      st_phase s = PhaseSolveConfig ->
      st_enospc s = false -> (* HARD KAMI GUARD *)
      st_strict_modes s = true ->
      st_action s = ActNone ->
      step s (mkState (st_enospc s) (st_strict_modes s) PhaseSolveConfig ActApplySSHFix)

  | StepAckConfig (s : State) :
      st_phase s = PhaseSolveConfig ->
      st_action s = ActApplySSHFix ->
      step s (mkState (st_enospc s) false PhaseDone ActNone).

Definition invariant (s : State) : Prop :=
  (st_action s = ActApplySSHFix -> st_enospc s = false) /\
  (st_phase s = PhaseSolveConfig -> st_enospc s = false) /\
  (st_phase s = PhaseDone -> st_enospc s = false).

Lemma invariant_step : forall s1 s2,
  invariant s1 -> step s1 s2 -> invariant s2.
Proof.
  intros s1 s2 [Hact [Hcfg Hdone]] Hstep.
  unfold invariant.
  destruct Hstep; simpl.
  - repeat split; intros; try discriminate.
  - repeat split; intros; try discriminate.
  - repeat split; intros; try discriminate; assumption.
  - repeat split; intros; try discriminate.
  - repeat split; intros; try discriminate; reflexivity.
  - repeat split; intros; try discriminate; assumption.
  - repeat split; intros; try discriminate; apply Hcfg; assumption.
Qed.

Inductive reachable (s0 : State) : State -> Prop :=
  | ReachInit : reachable s0 s0
  | ReachStep : forall s1 s2, reachable s0 s1 -> step s1 s2 -> reachable s0 s2.

Lemma invariant_initial : forall s0,
  is_initial s0 -> invariant s0.
Proof.
  intros s0 [Hphase Hact].
  unfold invariant. repeat split; intros;
    try (rewrite Hact in H; discriminate);
    try (rewrite Hphase in H; discriminate).
Qed.

Lemma invariant_reachable : forall s0 s,
  is_initial s0 -> reachable s0 s -> invariant s.
Proof.
  intros s0 s Hinit Hreach.
  induction Hreach.
  - apply invariant_initial. exact Hinit.
  - apply (invariant_step s1 s2); assumption.
Qed.

(* Main Causal Priority Theorem:
   In any reachable execution from an initial state, if ActApplySSHFix is executed,
   st_enospc is provably false. *)
Theorem causal_priority_invariant : forall s0 s,
  is_initial s0 ->
  reachable s0 s ->
  st_action s = ActApplySSHFix ->
  st_enospc s = false.
Proof.
  intros s0 s Hinit Hreach Hact.
  pose proof (invariant_reachable s0 s Hinit Hreach) as [Hsafe _].
  apply Hsafe. exact Hact.
Qed.
