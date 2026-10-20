# ADR: Native Node runtime and host gates for the pinned Handwired numeric core

Status: accepted and tested on Windows x64, Node 24.22.0.

Wirefit uses upstream Handwired commit `257856e3b221140acb4cc4460626b850c0bd4ff1`. Although the upstream application scripts use Bun, its Circuit implementation is a self-contained TypeScript module with no runtime imports. Native Node with the project's TypeScript compilation successfully builds a real Circuit, evaluates it, and backpropagates into parameter source cells. There is no demonstrated incompatibility that justifies a Bun worker dependency. Source execution tests use tsx; production compilation emits the vendored module under `dist/vendor/handwired/`.

Parameters are differentiable source cells, not host-only coefficients. Each piecewise segment has a real affine Circuit; the host chooses a segment using validated fixed knots. The host also computes the FP32 clamp value and strict-interior gradient mask at every parameter state. This follows the documented derivative contract and avoids both boolean STE and assumptions about upstream min/max macros. The complete batch denominator remains unchanged by saturation.

The upstream multiply and affine evaluation can lose the sign of zero. Consequently the training backend declares numeric FP32 forward compatibility and records bit discrepancies. The independent final evaluator retains exact FP32 bits, two rounding points, gradual underflow, finite intermediate rejection, and the equal clamp branch. A successful training call never upgrades mathematical proof or original-target validation. The parent verifier owns independent holdout and export verification after the returned candidate is frozen.

Analytic baseline is a complete box-constrained affine least-squares solution, including edge optima. It deliberately supports the officially declared affine/closed_form combination only. Reference and Handwired use the same seeded batches, initial parameters, restarts, parameter bounds, optimizer settings, candidate budget and final policies. They may have different low-order optimizer trajectories because actual Handwired gradients accumulate in FP32 while reference accumulation is float64; the artifact must report outcomes, not assume a speed or recovery advantage.

Rejected alternatives: replacing Handwired with a hand-coded derivative under its name; enabling straight-through boolean/index gradients; promoting training numeric agreement to final bitwise agreement; hiding failed/nonfinite samples; giving learner access to holdout; and adding Bun only because upstream demo scripts mention it.

Consequences: no GPU acceleration is claimed; Handwired remains optional, and simple affine closed-form recovery is expected to be cheaper. Future runtime/backprop changes require a new pinned source hash and rerunning the real gates in `docs/handwired-api-map.md`.
