pragma solidity >=0.5.0 <0.7.0;
pragma experimental ABIEncoderV2;

import "./PlonkCoreLib.sol";
import "hardhat/console.sol";

/// Plonk verifier
contract Plonk4SingleVerifierWithAccessToDNext {
    using PairingsBn254 for PairingsBn254.G1Point;
    using PairingsBn254 for PairingsBn254.G2Point;
    using PairingsBn254 for PairingsBn254.Fr;

    using TranscriptLibrary for TranscriptLibrary.Transcript;

    /**
     * State width is set to be 5.
     * | w_0 | w_1 | w_2 | w_3 | w_4
     * The verifier checks if the arithmetic constraint
     * holds for each the step i.
     *
     * q_arith[i] * ( q_0[i] * w0[i] + q_1[i] * w1[i] + q_2[i] * w2[i] + q_3[i] * w3[i] + q_m[i] * w0[i] * w1[i] + q_c[i] + q0next[i]*w0[nexti] - PI[i])
     * + alpha * ( z[i]*(w0[X] + 1*beta*X +gamma)(7)(13)(17) - z[wi]*(w0[X] + beta*sigma0[X] +gamma)()()()
     *               + alpha*L1[X]*(z[i] - 1) )
     * + alpha^3 * ( zlookup[i]*(qlookup[i]*v[i] +gamma)*(t[i] + beta*t[wi] + (beta+1)*gamma)
     *                - zlookup[wi]*gamma*(s[i] + beta*s[wi] + (beta+1)*gamma)
     *                   + alpha*L1[X]*(zlookup[i] - 1) + alpha^2 *Ln[X]*(zlookup[i] - 1) )
     * + alpha^6 * ( z_substring[wi] - z_substring[i] + q_substring0[i]*(w2[i]*w3[i] -w0[i]*w1[i])
     *                + alpha * q_substring_r0[i]*( w1[wi]*(w4[i]*w0[i] +w1[wi] -w1[i]) -w0[wi] )
     *                + alpha^2 * q_substring_r0[i]*( w3[wi]*(w4[i]*w2[i] +w3[wi] -w3[i]) -w2[wi] )
     *                + alpha^3 * z_substring[i] * L1[X]
     *                + alpha^4 * q_substring_r0[i]* w1[wi]*(w1[wi] - 1)
     *                + alpha^5 * q_substring_r0[i]* w3[wi]*(w3[wi] - 1)
     *              )
     * + alpha^12 * ( q_pubmatch[i] * w1[i] * (w0[i] - w1[i])
     *              )
     * = 0
     */

    uint256 constant STATE_WIDTH = 5;

    struct VerificationKey {
        uint128 domain_size;
        uint128 num_inputs;
        /// Generator of FFT domain: `omega` ^ `domain_size` = 1.
        PairingsBn254.Fr omega;
        /// commitments for selector polynomials `[q_0]`, `[q_1]`, `[q_2]`, `[q_3]`... , `[q_m]`, `[q_c]`, `[q0next]`
        /// , `[q_arith]`, `[q_lookup]`, `[q_table]`, [q_substring], [q_substring_r], [q_pubmatch]
        PairingsBn254.G1Point[STATE_WIDTH + 3 + 3 + 3] selector_commitments;
        /// commitment for permutation polynomials `[sigma_0]`, `[sigma_1]`, `[sigma_2]`, `[sigma_3]`...
        PairingsBn254.G1Point[STATE_WIDTH] permutation_commitments;
        /// commitment for tables polynomials `[table_0]`, `[table_1]`, `[table_2]`, `[table_3]`, `[table_4]`...
        PairingsBn254.G1Point[STATE_WIDTH + 1] tables_commitments;
        /// x element of G2: [x]_2 (beta_h)
        PairingsBn254.G2Point g2_x;
    }

    bytes32 vk1024hash;
    bytes32 vk2048hash;
    bytes32 srshash;

    struct Proof {
        /// input values, Fr array of length `verification_key.num_inputs`
        uint256[] input_values;
        /// commitments for witness polynomials `[w_0]`, `[w_1]`, `[w_2]`, `[w_3]`...
        PairingsBn254.G1Point[STATE_WIDTH] wire_commitments;
        /// commitment for grand product polynomial `[s]`
        PairingsBn254.G1Point sorted_lookup_commitment;
        /// commitment for grand product polynomial `[z]`
        PairingsBn254.G1Point grand_product_commitment;
        /// commitment for grand product polynomial `[z_lookup]`
        PairingsBn254.G1Point grand_product_lookup_commitment;
        /// commitment for grand sum polynomial `[z_substring]`
        PairingsBn254.G1Point z_substring_commitment;
        /// commitments for quotient polynomial `[t_0]`, `[t_1]`, `[t_2]`, `[t_3]`...
        PairingsBn254.G1Point[STATE_WIDTH] quotient_poly_commitments;
        /// evaluation `t(z)` for the quotient polynomial
        PairingsBn254.Fr quotient_polynomial_at_z;
        /// evaluation `r(z)`
        PairingsBn254.Fr linearization_polynomial_at_z;
        /// evaluations `w_0(z)`, `w_1(z)`, `w_2(z)`, `w_3(z)`...
        PairingsBn254.Fr[STATE_WIDTH] wire_values_at_z;
        /// evaluations `sigma_0(z)`, `sigma_1(z)`, `sigma_2(z)` ...
        PairingsBn254.Fr[STATE_WIDTH - 1] permutation_polynomials_at_z;
        /// evaluation `q_arith(z)`, `q_table(z)`, `q_lookup(z)`
        PairingsBn254.Fr[3] some_selectors_at_z;
        /// evaluation `table(z)`
        PairingsBn254.Fr table_at_z;
        /// evaluation `w0(z * omega)`
        PairingsBn254.Fr wire0_at_z_omega;
        /// evaluation `z(z * omega)` for the grand product polynomial at shifted location
        PairingsBn254.Fr grand_product_at_z_omega;
        /// evaluation `s(z * omega)`
        PairingsBn254.Fr sorted_lookup_at_z_omega;
        /// evaluation `z_lookup(z * omega)`
        PairingsBn254.Fr grand_product_lookup_at_z_omega;
        /// evaluation `table(z * omega)`
        PairingsBn254.Fr table_at_z_omega;
        /// evaluation `w1(z * omega)`
        PairingsBn254.Fr wire1_at_z_omega;
        /// evaluation `w2(z * omega)`
        PairingsBn254.Fr wire2_at_z_omega;
        /// evaluation `w3(z * omega)`
        PairingsBn254.Fr wire3_at_z_omega;
        /// evaluation `z_substring(z * omega)`
        PairingsBn254.Fr z_substring_at_z_omega;
        /// opening proof for all polynomial openings at `z`
        PairingsBn254.G1Point opening_at_z_proof;
        /// opening proof for all polynomial openings at `z * omega`
        PairingsBn254.G1Point opening_at_z_omega_proof;
    }

    struct PartialVerifierState {
        /// challenge s
        PairingsBn254.Fr eta;
        /// `beta` and `gamma` for grand product
        PairingsBn254.Fr beta;
        PairingsBn254.Fr gamma;
        /// combinator
        PairingsBn254.Fr alpha;
        /// `z` marks where the polynomial commitments should be opened
        PairingsBn254.Fr z;
        /// `v` for batched polynomial commitment opening a same location
        PairingsBn254.Fr v;
        /// `u` for combination of polynomial commitment opening proofs at `z` and `z * omega`
        PairingsBn254.Fr u;
        /// for constructing public inputs `pi(X)`
        PairingsBn254.Fr[] cached_lagrange_evals;
        /// Ln(z)
        PairingsBn254.Fr cached_lagrange_eval_Ln;
    }

    /// Evaluate one of the Lagrange polynomials associated with the FFT domain with `domain_size`
    /// `poly_num` marks which Lagrange polynomial to evaluate, ranging [0, `domain_size`)
    /// `omega` marks the domain generator
    /// `at` marks the location where the polynomial is evaluated, restricted to lie outside of the domain
    /**
     *            X^n - 1         1            w^i * (X^n - 1)
     * L_i(X) = ----------- * ------------ = -------------------
     *            X - w^i      n * w^{-i}       n * (X - w^i)
     */
    function evaluate_lagrange_poly_out_of_domain(
        uint256 poly_num,
        uint256 domain_size,
        PairingsBn254.Fr memory omega,
        PairingsBn254.Fr memory at
    ) internal view returns (PairingsBn254.Fr memory res) {
        require(poly_num < domain_size);
        PairingsBn254.Fr memory one = PairingsBn254.new_fr(1);
        PairingsBn254.Fr memory omega_power = omega.pow(poly_num);
        /// numerator: (X^n - 1) * w^i
        res = at.pow(domain_size);
        res.sub_assign(one);
        require(res.value != 0); // Vanishing polynomial can not be zero at point `at`
        res.mul_assign(omega_power);
        /// denumerator: (X - w^i) * n
        PairingsBn254.Fr memory den = PairingsBn254.copy(at);
        den.sub_assign(omega_power);
        den.mul_assign(PairingsBn254.new_fr(domain_size));

        den = den.inverse();

        res.mul_assign(den);
    }

    /// Evaluate a batch of the Lagrange polynomials associated with the FFT domain.
    /// Presumably, n Lagrange polynomial evaluations involves n inversion,
    /// whereas Montgomery batch inversion reduce it to only one.
    function batch_evaluate_lagrange_poly_out_of_domain(
        uint256[] memory poly_nums, //just [0,n)
        uint256 domain_size,
        PairingsBn254.Fr memory omega,
        PairingsBn254.Fr memory at
    )
        internal
        view
        returns (
            PairingsBn254.Fr[] memory res,
            PairingsBn254.Fr memory res_Ln,
            PairingsBn254.Fr memory return_zeta_pow_n
        )
    {
        PairingsBn254.Fr memory one = PairingsBn254.new_fr(1);
        PairingsBn254.Fr memory tmp_1 = PairingsBn254.new_fr(1);
        PairingsBn254.Fr memory tmp_2 = PairingsBn254.new_fr(domain_size);
        PairingsBn254.Fr memory vanishing_at_z = at.pow(domain_size);
        PairingsBn254.Fr memory return_zeta_pow_n = PairingsBn254.copy(
            vanishing_at_z
        );
        vanishing_at_z.sub_assign(one);

        // we can not have random point z be in domain
        require(vanishing_at_z.value != 0);
        PairingsBn254.Fr[] memory nums = new PairingsBn254.Fr[](
            poly_nums.length
        );
        PairingsBn254.Fr[] memory dens = new PairingsBn254.Fr[](
            poly_nums.length + 1
        ); //+1 for Ln

        /// compute numerators `nums` and denumerators `dens`, both of `poly_nums.length`
        // numerators in a form omega^i * (z^n - 1)
        // denoms in a form (z - omega^i) * N
        // tmp_1 = omega.pow(poly_nums[0]); // power of omega
        for (uint256 i = 0; i < poly_nums.length; i++) {
            //  = omega.pow(poly_nums[i]); // power of omega
            nums[i].assign(vanishing_at_z);
            nums[i].mul_assign(tmp_1);

            dens[i].assign(at); // (X - omega^i) * N
            dens[i].sub_assign(tmp_1);
            dens[i].mul_assign(tmp_2); // mul by domain size

            tmp_1.mul_assign(omega);
        }
        // add Ln = (z^n - 1)/(n(w*z - 1))
        PairingsBn254.Fr memory res_Ln = PairingsBn254.copy(vanishing_at_z);
        tmp_1.assign(omega);
        tmp_1.mul_assign(at);
        tmp_1.sub_assign(one);
        tmp_1.mul_assign(tmp_2);
        dens[dens.length - 1].assign(tmp_1); // Ln

        /// batch inversion of `dens`
        PairingsBn254.Fr[] memory partial_products = new PairingsBn254.Fr[](
            dens.length
        ); // Ln
        partial_products[0].assign(PairingsBn254.new_fr(1));
        for (uint256 i = 1; i < dens.length; i++) {
            partial_products[i].assign(partial_products[i - 1]);
            partial_products[i].mul_assign(dens[i - 1]);
        }

        tmp_2.assign(partial_products[partial_products.length - 1]);
        tmp_2.mul_assign(dens[dens.length - 1]);

        tmp_2 = tmp_2.inverse(); // tmp_2 contains a^-1 * b^-1 (with! the last one)

        PairingsBn254.Fr memory tmp3 = PairingsBn254.new_fr(0);
        for (uint256 i = dens.length - 1; i < dens.length; i--) {
            tmp3.assign(dens[i]);
            dens[i].assign(tmp_2); // all inversed
            dens[i].mul_assign(partial_products[i]); // clear lowest terms
            tmp_2.mul_assign(tmp3);
        }

        /// `nums[i] / dens[i]`
        for (uint256 i = 0; i < nums.length; i++) {
            nums[i].mul_assign(dens[i]);
        }

        // Ln
        res_Ln.mul_assign(dens[dens.length - 1]);
        // return nums;
        return (nums, res_Ln, return_zeta_pow_n);
    }

    function evaluate_vanishing(uint256 domain_size, PairingsBn254.Fr memory at)
        internal
        view
        returns (PairingsBn254.Fr memory res)
    {
        res = at.pow(domain_size);
        res.sub_assign(PairingsBn254.new_fr(1));
    }

    /// `verify_at_z` is called by `verify_initial`.
    /// It performs the finite field part of the verification.
    function verify_at_z(
        PairingsBn254.Fr memory zeta_n,
        PartialVerifierState memory state,
        Proof memory proof,
        VerificationKey memory vk
    ) internal view returns (bool) {
        /// lhs = t(z) * v(z)
        PairingsBn254.Fr memory lhs = PairingsBn254.copy(zeta_n);
        lhs.sub_assign(PairingsBn254.new_fr(1));
        require(lhs.value != 0); // we can not check a polynomial relationship if point `z` is in the domain
        lhs.mul_assign(proof.quotient_polynomial_at_z);

        /** rhs = r(z) - q_arith(z) * pi(z) - (r_permu + r_lookup + r_substring)
         *
         *      alpha * (                                   |
         *          (w_0(z) + beta * sigma_0(z) + gamma)    |
         *          * (w_1(z) + beta * sigma_1(z) + gamma)  |  "r_permu"
         *          * (w_2(z) + beta * sigma_2(z) + gamma)  |
         *          * (w_3(z) + gamma) * z(zw)              |
         *          + alpha * L1(z)                         |
         *      )                                           |
         *
         *      alpha^3 * (                                 |
         *          zlookup(zw) * gamma                     |
         *              * (beta * s(zw) + (beta+1)gamma)    |  "r_lookup"
         *          + alpha * L1(z)                         |
         *          + alpha^2 * Ln(z)                       |
         *      )                                           |
         *      alpha^6 * (                                 |
         *          - z_substring(zw)                       |  "r_substring"
         *      )                                           |
         */

        /// rhs = r(z)
        PairingsBn254.Fr memory rhs = PairingsBn254.copy(
            proof.linearization_polynomial_at_z
        );
        // public inputs
        PairingsBn254.Fr memory inputs_term = PairingsBn254.new_fr(0);
        PairingsBn254.Fr memory tmp = PairingsBn254.new_fr(0);
        for (uint256 i = 0; i < proof.input_values.length; i++) {
            tmp.assign(state.cached_lagrange_evals[i]);
            tmp.mul_assign(PairingsBn254.new_fr(proof.input_values[i]));
            inputs_term.add_assign(tmp);
        }

        // q_arith(z) * pi(x)
        inputs_term.mul_assign(proof.some_selectors_at_z[0]);
        /// rhs -= q_arith(z) * pi(x)
        rhs.sub_assign(inputs_term);

        /// rhs -= "r_complement"
        PairingsBn254.Fr memory quotient_challenge = PairingsBn254.copy(
            state.alpha
        );

        PairingsBn254.Fr memory r_permu = PairingsBn254.copy(
            proof.grand_product_at_z_omega
        );
        //"r_permu"
        for (uint256 i = 0; i < STATE_WIDTH - 1; i++) {
            tmp.assign(proof.permutation_polynomials_at_z[i]);
            tmp.mul_assign(state.beta);
            tmp.add_assign(state.gamma);
            tmp.add_assign(proof.wire_values_at_z[i]);

            r_permu.mul_assign(tmp);
        }
        //(w_4(z) + gamma)
        tmp.assign(state.gamma);
        tmp.add_assign(proof.wire_values_at_z[STATE_WIDTH - 1]);
        r_permu.mul_assign(tmp);

        //alpha * L1(z) (reuse var inputs_term)
        inputs_term.assign(state.cached_lagrange_evals[0]);
        inputs_term.mul_assign(state.alpha);
        r_permu.add_assign(inputs_term);

        r_permu.mul_assign(state.alpha);
        rhs.sub_assign(r_permu);

        //alpha^2
        quotient_challenge.mul_assign(state.alpha);
        //r_lookup (reuse var r_permu)
        r_permu.assign(proof.sorted_lookup_at_z_omega);
        r_permu.mul_assign(state.beta);

        tmp.assign(state.beta);
        tmp.add_assign(PairingsBn254.new_fr(1));
        tmp.mul_assign(state.gamma);
        r_permu.add_assign(tmp);

        r_permu.mul_assign(proof.grand_product_lookup_at_z_omega);
        r_permu.mul_assign(state.gamma);

        // + alpha * L1(z)
        r_permu.add_assign(inputs_term);

        //alpha^2 * Ln(z) (reuse var inputs_term)
        inputs_term.assign(state.cached_lagrange_eval_Ln);
        inputs_term.mul_assign(quotient_challenge);
        r_permu.add_assign(inputs_term);

        //alpha^3
        quotient_challenge.mul_assign(state.alpha);
        // r_lookup * alpha^3
        r_permu.mul_assign(quotient_challenge);

        rhs.sub_assign(r_permu);

        //alpha^6
        tmp.assign(quotient_challenge);
        quotient_challenge.mul_assign(tmp);
        // "r_substring" (reuse var)
        // alpha^6 * z_substring(zw)
        quotient_challenge.mul_assign(proof.z_substring_at_z_omega);

        rhs.add_assign(quotient_challenge); //over

        return lhs.value == rhs.value;
    }

    /**
     * [D] = v[r] + v*u[z] + v2*u[s] + v3*u[zlookup]
     * where 
     * [r] = qarith([q_c] + w_0[q_0] + w_1[q_1] + w_2[q_2] + w_3[q_3] + w_0*w_1[q_m] + w0zw[q0next])
     *       + alpha * ( (w_0(z) + bata * z + gamma)(w_1(z) + K_1 * bata * z + gamma)
     *              *(w_2(z) + k_2 * bata * z + gamma)(w_3(z) + k_3 * bata * z + gamma)
     *          + alpha * L_0(z) ) * [z]
     *       - alpha
     *          * (w_0(z) + beta * sigma_0(z) + gamma)
     *          * (w_1(z) + beta * sigma_1(z) + gamma)
     *          * (w_2(z) + beta * sigma_2(z) + gamma)
     *          * beta * z(z*omega) * [sigma_3]
     *       + alpha^3 * (
                (qlookup(w0+ eta*w1 + ... + eta4*qtable) + gamma) * (table + beta*table_zw + gamma(1+beta))
                + alpha * L_0(z) + alpha^2 * Ln(z)
                ) *[zlookup]
             - alpha^3 * (gamma * zlookup_zw) * [s]

     *       + alpha^6 * (w2[z]*w3[z] -w0[z]*w1[z]) *[q_substring0]
     *       + alpha^6 * (  
     *          + alpha * ( w1[zw]*(w4[z]*w0[z] +w1[zw] -w1[z]) -w0[zw] ) 
     *          + alpha^2 * ( w3[zw]*(w4[z]*w2[z] +w3[zw] -w3[z]) -w2[zw] )  
     *          + alpha^4 * w1[zw]*(w1[zw] - 1)     
     *          + alpha^5 * w3[zw]*(w3[zw] - 1)     
     *         ) *[q_substring_r0]
     *       + alpha^6 * (alpha^3 * L1[z] - 1) *[z_substring]
     *       + alpha^12 * (
                w1[z] * (w0[z] - w1[z])
                ) *[q_pubmatch]
                
     */
    function reconstruct_d(
        PartialVerifierState memory state,
        Proof memory proof,
        VerificationKey memory vk
    )
        internal
        view
        returns (
            PairingsBn254.G1Point memory res,
            PairingsBn254.Fr memory out_vu
        )
    {
        PairingsBn254.Fr memory one = PairingsBn254.new_fr(1);
        /// [q_c]
        res = PairingsBn254.copy_g1(vk.selector_commitments[STATE_WIDTH + 1]);

        // qarith*v
        PairingsBn254.Fr memory tmp_fr0 = PairingsBn254.copy(
            proof.some_selectors_at_z[0]
        );
        tmp_fr0.mul_assign(state.v);
        // qarith*v[q_c]
        res.point_mul_assign(tmp_fr0);

        // qarith*v*w0
        PairingsBn254.Fr memory tmp_fr1 = PairingsBn254.copy(tmp_fr0);
        tmp_fr1.mul_assign(proof.wire_values_at_z[0]);

        PairingsBn254.G1Point memory tmp_g1 = PairingsBn254.P1();
        PairingsBn254.Fr memory tmp_fr = PairingsBn254.new_fr(0);

        // qarith*v*w0 [q0]
        tmp_g1 = vk.selector_commitments[0].point_mul(tmp_fr1);
        res.point_add_assign(tmp_g1);

        // qarith*v*w0*w1
        tmp_fr1.mul_assign(proof.wire_values_at_z[1]);
        // qarith*v*w0*w1 [qm]
        tmp_g1 = vk.selector_commitments[STATE_WIDTH].point_mul(tmp_fr1);
        res.point_add_assign(tmp_g1);

        for (uint256 i = 1; i < STATE_WIDTH; i++) {
            // qarith*v*wi [qi]
            tmp_fr1.assign(tmp_fr0);
            tmp_fr1.mul_assign(proof.wire_values_at_z[i]);
            tmp_g1 = vk.selector_commitments[i].point_mul(tmp_fr1);
            res.point_add_assign(tmp_g1);
        }
        // qarith*v*w0zw [q0next]
        tmp_fr1.assign(tmp_fr0);
        tmp_fr1.mul_assign(proof.wire0_at_z_omega);
        tmp_g1 = vk.selector_commitments[STATE_WIDTH + 2].point_mul(tmp_fr1);
        res.point_add_assign(tmp_g1);

        // v*alpha
        tmp_fr0.assign(state.v);
        tmp_fr0.mul_assign(state.alpha);

        // beta*z
        tmp_fr.assign(state.z);
        tmp_fr.mul_assign(state.beta);

        //(w_0(z) + bata * z + gamma)
        PairingsBn254.Fr memory grand_product_part_at_z = PairingsBn254.copy(
            tmp_fr
        );
        grand_product_part_at_z.add_assign(proof.wire_values_at_z[0]);
        grand_product_part_at_z.add_assign(state.gamma);
        // *(w_1(z) + K_1 * bata * z + gamma)
        tmp_fr1.assign(tmp_fr);
        tmp_fr1.mul_assign(PairingsBn254.new_fr(7));
        tmp_fr1.add_assign(proof.wire_values_at_z[1]);
        tmp_fr1.add_assign(state.gamma);
        grand_product_part_at_z.mul_assign(tmp_fr1);
        // *(w_2(z) + k_2 * bata * z + gamma)
        tmp_fr1.assign(tmp_fr);
        tmp_fr1.mul_assign(PairingsBn254.new_fr(13));
        tmp_fr1.add_assign(proof.wire_values_at_z[2]);
        tmp_fr1.add_assign(state.gamma);
        grand_product_part_at_z.mul_assign(tmp_fr1);
        // *(w_3(z) + k_3 * bata * z + gamma)
        tmp_fr1.assign(tmp_fr);
        tmp_fr1.mul_assign(PairingsBn254.new_fr(17));
        tmp_fr1.add_assign(proof.wire_values_at_z[3]);
        tmp_fr1.add_assign(state.gamma);
        grand_product_part_at_z.mul_assign(tmp_fr1);
        // *(w_4(z) + k_4 * bata * z + gamma)
        tmp_fr1.assign(tmp_fr);
        tmp_fr1.mul_assign(PairingsBn254.new_fr(23));
        tmp_fr1.add_assign(proof.wire_values_at_z[4]);
        tmp_fr1.add_assign(state.gamma);
        grand_product_part_at_z.mul_assign(tmp_fr1);

        // + alpha * L_0(z)
        tmp_fr1.assign(state.cached_lagrange_evals[0]);
        tmp_fr1.mul_assign(state.alpha);
        grand_product_part_at_z.add_assign(tmp_fr1);
        // * v*alpha
        grand_product_part_at_z.mul_assign(tmp_fr0);

        // v*u
        PairingsBn254.Fr memory out_vu = PairingsBn254.copy(state.u);
        out_vu.mul_assign(state.v);

        // + v*u
        grand_product_part_at_z.add_assign(out_vu);
        // * [z]
        tmp_g1 = proof.grand_product_commitment.point_mul(
            grand_product_part_at_z
        );
        res.point_add_assign(tmp_g1);

        // (w_0(z) + beta * sigma_0(z) + gamma) (reuse var grand_product_part_at_z)
        grand_product_part_at_z.assign(proof.permutation_polynomials_at_z[0]);
        grand_product_part_at_z.mul_assign(state.beta);
        grand_product_part_at_z.add_assign(proof.wire_values_at_z[0]);
        grand_product_part_at_z.add_assign(state.gamma);
        for (uint256 i = 1; i < STATE_WIDTH - 1; i++) {
            // *(w_i(z) + beta * sigma_i(z) + gamma)
            tmp_fr.assign(proof.permutation_polynomials_at_z[i]);
            tmp_fr.mul_assign(state.beta);
            tmp_fr.add_assign(proof.wire_values_at_z[i]);
            tmp_fr.add_assign(state.gamma);
            grand_product_part_at_z.mul_assign(tmp_fr);
        }
        // *beta * z(z*omega) * v*alpha * [sigma_last]
        grand_product_part_at_z.mul_assign(state.beta);
        grand_product_part_at_z.mul_assign(proof.grand_product_at_z_omega);
        grand_product_part_at_z.mul_assign(tmp_fr0);
        tmp_g1 = vk.permutation_commitments[STATE_WIDTH - 1].point_mul(
            grand_product_part_at_z
        );
        res.point_sub_assign(tmp_g1);

        // v*alpha^3
        tmp_fr0.mul_assign(state.alpha);
        tmp_fr0.mul_assign(state.alpha);

        // v2*u
        out_vu.mul_assign(state.v);

        // cal [s] first
        //(gamma * zlookup_zw)
        tmp_fr.assign(proof.grand_product_lookup_at_z_omega);
        tmp_fr.mul_assign(state.gamma);
        // * v*alpha^3
        tmp_fr.mul_assign(tmp_fr0);
        // - v2*u
        tmp_fr.sub_assign(out_vu);
        // * [s]
        tmp_g1 = proof.sorted_lookup_commitment.point_mul(tmp_fr);
        res.point_sub_assign(tmp_g1);

        // v3*u
        out_vu.mul_assign(state.v);

        // combinator eta
        PairingsBn254.Fr memory tmp_fr2 = PairingsBn254.copy(state.eta);

        // [zlookup]
        // w0+ eta*w1 + ... + eta5*qtable
        grand_product_part_at_z.assign(proof.wire_values_at_z[0]);
        for (uint256 i = 1; i < STATE_WIDTH; i++) {
            tmp_fr.assign(proof.wire_values_at_z[i]);
            tmp_fr.mul_assign(tmp_fr2);
            grand_product_part_at_z.add_assign(tmp_fr);

            tmp_fr2.mul_assign(state.eta);
        }
        // eta^5 * qtable
        tmp_fr.assign(proof.some_selectors_at_z[1]);
        tmp_fr.mul_assign(tmp_fr2);
        grand_product_part_at_z.add_assign(tmp_fr);
        // *qlookup + gamma
        grand_product_part_at_z.mul_assign(proof.some_selectors_at_z[2]);
        grand_product_part_at_z.add_assign(state.gamma);

        // * (table + beta*table_zw + gamma(1+beta))
        // gamma(1+beta)
        tmp_fr.assign(state.beta);
        tmp_fr.add_assign(one);
        tmp_fr.mul_assign(state.gamma);
        // + beta*table_zw + table
        tmp_fr1.assign(proof.table_at_z_omega);
        tmp_fr1.mul_assign(state.beta);
        tmp_fr.add_assign(tmp_fr1);
        tmp_fr.add_assign(proof.table_at_z);
        // *
        grand_product_part_at_z.mul_assign(tmp_fr);

        //+ alpha * L_0(z) + alpha^2 * Ln(z)
        tmp_fr1.assign(state.cached_lagrange_evals[0]);
        tmp_fr.assign(state.alpha);
        tmp_fr1.mul_assign(tmp_fr);
        grand_product_part_at_z.add_assign(tmp_fr1);
        tmp_fr.mul_assign(state.alpha);
        tmp_fr.mul_assign(state.cached_lagrange_eval_Ln);
        grand_product_part_at_z.add_assign(tmp_fr);

        // * v*alpha^3
        grand_product_part_at_z.mul_assign(tmp_fr0);
        // + v3*u
        grand_product_part_at_z.add_assign(out_vu);
        // * [zlookup]
        tmp_g1 = proof.grand_product_lookup_commitment.point_mul(
            grand_product_part_at_z
        );
        res.point_add_assign(tmp_g1);

        // "substring"
        // first [q_substring_r0]
        // comb alpha
        tmp_fr.assign(state.alpha);
        // w4[z]*w0[z] (reuse var)
        grand_product_part_at_z.assign(proof.wire_values_at_z[4]);
        grand_product_part_at_z.mul_assign(proof.wire_values_at_z[0]);
        // +w1[zw] -w1[z]
        grand_product_part_at_z.add_assign(proof.wire1_at_z_omega);
        grand_product_part_at_z.sub_assign(proof.wire_values_at_z[1]);
        // w1[zw]*(w4[z]*w0[z] +w1[zw] -w1[z]) -w0[zw]
        grand_product_part_at_z.mul_assign(proof.wire1_at_z_omega);
        grand_product_part_at_z.sub_assign(proof.wire0_at_z_omega);
        // *alpha
        grand_product_part_at_z.mul_assign(tmp_fr);
        tmp_fr.mul_assign(state.alpha);

        // w3[zw]*(w4[z]*w2[z] +w3[zw] -w3[z]) -w2[zw] (reuse var)
        tmp_fr1.assign(proof.wire_values_at_z[4]);
        tmp_fr1.mul_assign(proof.wire_values_at_z[2]);
        tmp_fr1.add_assign(proof.wire3_at_z_omega);
        tmp_fr1.sub_assign(proof.wire_values_at_z[3]);
        tmp_fr1.mul_assign(proof.wire3_at_z_omega);
        tmp_fr1.sub_assign(proof.wire2_at_z_omega);
        // *alpha2
        tmp_fr1.mul_assign(tmp_fr);
        grand_product_part_at_z.add_assign(tmp_fr1);

        // alpha3
        tmp_fr.mul_assign(state.alpha);
        // v*alpha^6
        tmp_fr0.mul_assign(tmp_fr);

        // w1[zw]*(w1[zw] - 1)
        tmp_fr1.assign(proof.wire1_at_z_omega);
        tmp_fr1.sub_assign(one);
        tmp_fr1.mul_assign(proof.wire1_at_z_omega);
        tmp_fr2.assign(tmp_fr);
        tmp_fr2.mul_assign(state.alpha);
        // *alpha4
        tmp_fr1.mul_assign(tmp_fr2);
        grand_product_part_at_z.add_assign(tmp_fr1);

        // w3[zw]*(w3[zw] - 1)
        tmp_fr1.assign(proof.wire3_at_z_omega);
        tmp_fr1.sub_assign(one);
        tmp_fr1.mul_assign(proof.wire3_at_z_omega);
        tmp_fr2.mul_assign(state.alpha);
        // *alpha5
        tmp_fr1.mul_assign(tmp_fr2);
        grand_product_part_at_z.add_assign(tmp_fr1);

        // * v*alpha^6
        grand_product_part_at_z.mul_assign(tmp_fr0);
        // * [q_substring_r0]
        tmp_g1 = vk.selector_commitments[STATE_WIDTH + 3 + 3 + 1].point_mul(
            grand_product_part_at_z
        );
        res.point_add_assign(tmp_g1);

        // (alpha^3 * L1[z] - 1) *[z_substring]
        grand_product_part_at_z.assign(state.cached_lagrange_evals[0]);
        grand_product_part_at_z.mul_assign(tmp_fr);
        grand_product_part_at_z.sub_assign(one);
        // * v*alpha^6
        grand_product_part_at_z.mul_assign(tmp_fr0);
        // * [z_substring]
        tmp_g1 = proof.z_substring_commitment.point_mul(
            grand_product_part_at_z
        );
        res.point_add_assign(tmp_g1);

        // (w2[z]*w3[z] -w0[z]*w1[z]) *[q_substring0]
        grand_product_part_at_z.assign(proof.wire_values_at_z[2]);
        grand_product_part_at_z.mul_assign(proof.wire_values_at_z[3]);
        tmp_fr1.assign(proof.wire_values_at_z[0]);
        tmp_fr1.mul_assign(proof.wire_values_at_z[1]);
        grand_product_part_at_z.sub_assign(tmp_fr1);
        // * v*alpha^6
        grand_product_part_at_z.mul_assign(tmp_fr0);
        // * [q_substring0]
        tmp_g1 = vk.selector_commitments[STATE_WIDTH + 3 + 3].point_mul(
            grand_product_part_at_z
        );
        res.point_add_assign(tmp_g1);

        // "pub match"
        //alpha^6
        tmp_fr2.mul_assign(state.alpha);
        //v*alpha^12
        tmp_fr0.mul_assign(tmp_fr2);
        // w1[z] * (w0[z] - w1[z])
        grand_product_part_at_z.assign(proof.wire_values_at_z[0]);
        grand_product_part_at_z.sub_assign(proof.wire_values_at_z[1]);
        grand_product_part_at_z.mul_assign(proof.wire_values_at_z[1]);
        // * v*alpha^12
        grand_product_part_at_z.mul_assign(tmp_fr0);
        // * [q_pubmatch]
        tmp_g1 = vk.selector_commitments[STATE_WIDTH + 3 + 3 + 2].point_mul(
            grand_product_part_at_z
        );
        res.point_add_assign(tmp_g1);

        return (res, out_vu);
    }

    /// The function `verify_commitments` batch verifies the evaluations constained in the proof of
    /// their corresponding commitments
    /**
     * 1. the proof element `r(z)`
     *    should be checked against polynomial commitment [r]
     *
     * All polynomial commitments are aggregated into [F], whereas evaluations are aggregated into aggregated value e.
     * Two opening proof is required, `[W_z]` for openings at `z`, and `[W_z_omega]` for openings at `z * omega`.
     * The polynomial commitments are finally checked by two pairing operations
     * Pairing([F] - e * [1] + z * [W_z] + u * z * omega * [W_z_omega], [1]_2) - Pairing([W_z] + u * [W_z_omega], x * [1]_2) ?= 0.

     // e( Σ[(u^i * ζi) * πi + u^i * commi)] - Σ[u^i * evali]*G0)], H0) = e(Σ[u^i * πi], H1).
     *
     * `reconstruct_d` computes [D] which is an aggregation of step 1 and 5,
     * both of which involves commitment [z].
     */
    function verify_commitments(
        PairingsBn254.Fr memory zeta_n,
        PartialVerifierState memory state,
        Proof memory proof,
        VerificationKey memory vk
    ) internal view returns (bool) {
        /** [F] = [t_0] + z^n * [t_1] + z^{2n} * [t_2] + z^{3n} * [t_3]
         *      + v * [r]
         *      + v^2 * [w_0] + v^3 * [w_1] + v^4 * [w_2] + v^5 * [w_3] + v^6 * [w_4]
         *      + v^7 * [sigma_0] + v^8 * [sigma_1] + v^9 * [sigma_2] + v^10 * [sigma_3]
         *      + v^11[qarith] + v^12[qtable] + v^13[qlookup]
         *      + v^14 * ([table0] +eta[table1] +eta2[]... +eta4[])
         *      + u[w_0] + uv[z] + uv2[s] + uv3[zlookup]
         *      + uv4 * ([table0] +eta[table1] +eta2[]... +eta4[])
         *      + uv5 * [w_1] + uv6 * [w_2] + uv7 * [w_3] + uv8 [z_substring]
         */
        /// [D] = v[r] + v*u[z] + v2*u[s] + v3*u[zlookup] . v3*u
        (
            PairingsBn254.G1Point memory commitment_aggregation,
            PairingsBn254.Fr memory out_vu
        ) = reconstruct_d(state, proof, vk);

        /// [F] = [t_0] + z^n * [t_1] + z^{2n} * [t_2] + z^{3n} * [t_3] ...
        PairingsBn254.G1Point memory tmp_g1 = PairingsBn254.P1();

        commitment_aggregation.point_add_assign(
            proof.quotient_poly_commitments[0]
        );
        PairingsBn254.Fr memory tmp_fr = PairingsBn254.new_fr(1);
        for (uint256 i = 1; i < STATE_WIDTH; i++) {
            tmp_fr.mul_assign(zeta_n);
            tmp_g1 = proof.quotient_poly_commitments[i].point_mul(tmp_fr);
            commitment_aggregation.point_add_assign(tmp_g1);
        }

        PairingsBn254.Fr memory aggregation_challenge = PairingsBn254.copy(
            state.v
        );
        /// [F] += [D]
        // commitment_aggregation.point_add_assign(d);

        /// [F] += (v^2 +u)[w_0] + v^3[w_1] + v^4[w_2] + v^5[w_3] + v^6[w_4]
        // + uv5 * [w_1] + uv6 * [w_2] + uv7 * [w_3]
        aggregation_challenge.mul_assign(state.v);
        PairingsBn254.Fr memory tmp_fr0 = PairingsBn254.copy(
            aggregation_challenge
        );
        tmp_fr0.add_assign(state.u);
        tmp_g1 = proof.wire_commitments[0].point_mul(tmp_fr0);
        commitment_aggregation.point_add_assign(tmp_g1);
        tmp_fr.assign(out_vu);
        tmp_fr.mul_assign(aggregation_challenge);

        for (uint256 i = 1; i < 4; i++) {
            aggregation_challenge.mul_assign(state.v);

            tmp_fr0.assign(aggregation_challenge);
            tmp_fr0.add_assign(tmp_fr);
            tmp_g1 = proof.wire_commitments[i].point_mul(tmp_fr0);
            commitment_aggregation.point_add_assign(tmp_g1);

            tmp_fr.mul_assign(state.v);
        }
        for (uint256 i = 4; i < STATE_WIDTH; i++) {
            aggregation_challenge.mul_assign(state.v);

            tmp_g1 = proof.wire_commitments[i].point_mul(aggregation_challenge);
            commitment_aggregation.point_add_assign(tmp_g1);
        }

        /// [F] += v^7 * [sigma_0] + v^8 * [sigma_1] + v^9 * [sigma_2] + v^10 * [sigma_3]
        for (uint256 i = 0; i < STATE_WIDTH - 1; i++) {
            aggregation_challenge.mul_assign(state.v);
            tmp_g1 = vk.permutation_commitments[i].point_mul(
                aggregation_challenge
            );
            commitment_aggregation.point_add_assign(tmp_g1);
        }

        /// [F] += v^11[qarith] + v^12[qtable] + v^13[qlookup]
        aggregation_challenge.mul_assign(state.v);
        tmp_g1 = vk.selector_commitments[STATE_WIDTH + 3].point_mul(
            aggregation_challenge
        );
        commitment_aggregation.point_add_assign(tmp_g1);
        aggregation_challenge.mul_assign(state.v);
        tmp_g1 = vk.selector_commitments[STATE_WIDTH + 5].point_mul(
            aggregation_challenge
        );
        commitment_aggregation.point_add_assign(tmp_g1);
        aggregation_challenge.mul_assign(state.v);
        tmp_g1 = vk.selector_commitments[STATE_WIDTH + 4].point_mul(
            aggregation_challenge
        );
        commitment_aggregation.point_add_assign(tmp_g1);

        //([table0] +eta[table1] +eta2[]... +eta5[])
        PairingsBn254.G1Point memory tables_comms_combine = PairingsBn254
            .copy_g1(vk.tables_commitments[0]);
        tmp_fr0.assign(state.eta);
        for (uint256 i = 0; i < STATE_WIDTH; i++) {
            tmp_g1 = vk.tables_commitments[i + 1].point_mul(tmp_fr0);
            tables_comms_combine.point_add_assign(tmp_g1);

            tmp_fr0.mul_assign(state.eta);
        }
        // [F] += (v^14 +uv4) * ([table0] +eta[table1] +eta2[]... +eta5[])
        aggregation_challenge.add_assign(out_vu);
        aggregation_challenge.mul_assign(state.v);
        tmp_g1 = tables_comms_combine.point_mul(aggregation_challenge);
        commitment_aggregation.point_add_assign(tmp_g1);

        // [F] += uv8 [z_substring]
        tmp_g1 = proof.z_substring_commitment.point_mul(tmp_fr);
        commitment_aggregation.point_add_assign(tmp_g1);

        /// Done with [F]. Then compute aggregated value.
        /** e = t(z)
         *      + v * r(z)
         *      + v^2 * w_0(z) + v^3 * w_1(z) * v^4 * w_2(z) + v^5 * w_3(z) + v^6 * w_4(z)
         *      + v^7 * sigma_0(z) + v^8 * sigma_1(z) + v^9 * sigma_2(z) + v^10 * sigma_3(z)
         *      + v^11 qarith(z) + v^12 qtable(z) + v^13 qlookup(z) + v^14 table(z)
         *      + u* w0(zomega) + u*v z(zomega) + u*v2 s(zomega) + u*v3 zlookup(zomega)
         *      + u*v4 table(zomega)
         *      + uv5 * w1(zomega) + uv6 * w2(zomega) + uv7 * w3(zomega) + uv8 z_substring(zomega)
         */
        // collect opening values
        aggregation_challenge.assign(state.v);

        PairingsBn254.Fr memory aggregated_value = PairingsBn254.copy(
            proof.quotient_polynomial_at_z
        );

        tmp_fr.assign(proof.linearization_polynomial_at_z);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);
        // + v2*w0 + ... + v5*w3 ...
        for (uint256 i = 0; i < STATE_WIDTH; i++) {
            aggregation_challenge.mul_assign(state.v);
            tmp_fr.assign(proof.wire_values_at_z[i]);
            tmp_fr.mul_assign(aggregation_challenge);
            aggregated_value.add_assign(tmp_fr);
        }
        // + v7*sigma0 + ... + v8*sigma2 ...
        for (uint256 i = 0; i < STATE_WIDTH - 1; i++) {
            aggregation_challenge.mul_assign(state.v);
            tmp_fr.assign(proof.permutation_polynomials_at_z[i]);
            tmp_fr.mul_assign(aggregation_challenge);
            aggregated_value.add_assign(tmp_fr);
        }
        // + v^11 qarith(z) + v^12 qtable(z) + v^13 qlookup(z) + v^14 table(z)
        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.some_selectors_at_z[0]);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.some_selectors_at_z[1]);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.some_selectors_at_z[2]);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.table_at_z);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        // + u* w0(zomega) + u*v z(zomega) + u*v2 s(zomega) + u*v3 zlookup(zomega)
        aggregation_challenge.assign(state.u);
        tmp_fr.assign(proof.wire0_at_z_omega);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.grand_product_at_z_omega);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.sorted_lookup_at_z_omega);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.grand_product_lookup_at_z_omega);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);
        // + u*v4 table(zomega)
        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.table_at_z_omega);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        // + uv5 * w1(zomega) + uv6 * w2(zomega) + uv7 * w3(zomega) + uv8 z_substring(zomega)
        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.wire1_at_z_omega);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.wire2_at_z_omega);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.wire3_at_z_omega);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        aggregation_challenge.mul_assign(state.v);
        tmp_fr.assign(proof.z_substring_at_z_omega);
        tmp_fr.mul_assign(aggregation_challenge);
        aggregated_value.add_assign(tmp_fr);

        // e(z[Wz] +uzw[Wzw] +[F] -e[1], g2) = e([Wz] +u[Wzw], g2_x)
        commitment_aggregation.point_sub_assign(
            PairingsBn254.P1().point_mul(aggregated_value)
        );

        commitment_aggregation.point_add_assign(
            proof.opening_at_z_proof.point_mul(state.z)
        );

        tmp_fr.assign(state.z);
        tmp_fr.mul_assign(vk.omega);
        tmp_fr.mul_assign(state.u);
        commitment_aggregation.point_add_assign(
            proof.opening_at_z_omega_proof.point_mul(tmp_fr)
        );

        PairingsBn254.G1Point memory pair_with_x = proof
            .opening_at_z_omega_proof
            .point_mul(state.u);
        pair_with_x.point_add_assign(proof.opening_at_z_proof);
        pair_with_x.negate();

        return
            PairingsBn254.pairingProd2(
                commitment_aggregation,
                PairingsBn254.P2(),
                pair_with_x,
                vk.g2_x
            );
    }

    /** `verify_initial` prepares the verifier state (by reading the proof,
     *   generating the challenges along the way, and batch evaluating largange polynomials),
     *   and calls `verify_at_z` which performs the finite-field part of the verification*/
    function verify_initial(
        PartialVerifierState memory state,
        Proof memory proof,
        VerificationKey memory vk,
        bytes32 vkhash
    ) internal view returns (bool, PairingsBn254.Fr memory return_zeta_pow_n) {
        require(proof.input_values.length == vk.num_inputs);
        // require(vk.num_inputs >= 1);
        TranscriptLibrary.Transcript memory transcript = TranscriptLibrary
            .new_transcript();

        // add srshash first
        transcript.update_with_u256(uint256(srshash));

        // add circuit
        transcript.update_with_u256(uint256(vkhash));

        for (uint256 i = 0; i < vk.num_inputs; i++) {
            transcript.update_with_u256(proof.input_values[i]);
        }

        //step 1
        for (uint256 i = 0; i < STATE_WIDTH; i++) {
            transcript.update_with_g1(proof.wire_commitments[i]);
        }
        state.eta = transcript.get_challenge();

        //step 2
        transcript.update_with_g1(proof.sorted_lookup_commitment);
        state.beta = transcript.get_challenge();
        state.gamma = transcript.get_challenge();

        //step 3
        transcript.update_with_g1(proof.grand_product_commitment);
        transcript.update_with_g1(proof.grand_product_lookup_commitment);
        transcript.update_with_g1(proof.z_substring_commitment);
        state.alpha = transcript.get_challenge();

        //step 4
        for (uint256 i = 0; i < STATE_WIDTH; i++) {
            transcript.update_with_g1(proof.quotient_poly_commitments[i]);
        }
        state.z = transcript.get_challenge();

        // we need L0 even there's no pubinput
        uint256 tmp = 0;
        if (vk.num_inputs == 0) {
            tmp = 1;
        }

        uint256[] memory lagrange_poly_numbers = new uint256[](
            vk.num_inputs + tmp
        );
        for (uint256 i = 0; i < lagrange_poly_numbers.length; i++) {
            lagrange_poly_numbers[i] = i;
        }

        PairingsBn254.Fr memory return_zeta_pow_n;
        (
            state.cached_lagrange_evals,
            state.cached_lagrange_eval_Ln,
            return_zeta_pow_n
        ) = batch_evaluate_lagrange_poly_out_of_domain(
            lagrange_poly_numbers,
            vk.domain_size,
            vk.omega,
            state.z
        );

        bool valid = verify_at_z(return_zeta_pow_n, state, proof, vk);
        if (valid == false) {
            return (false, return_zeta_pow_n);
        }

        //add evaluations z
        transcript.update_with_fr(proof.quotient_polynomial_at_z);
        transcript.update_with_fr(proof.linearization_polynomial_at_z);
        for (uint256 i = 0; i < STATE_WIDTH; i++) {
            transcript.update_with_fr(proof.wire_values_at_z[i]);
        }
        for (uint256 i = 0; i < STATE_WIDTH - 1; i++) {
            transcript.update_with_fr(proof.permutation_polynomials_at_z[i]);
        }
        for (uint256 i = 0; i < 3; i++) {
            transcript.update_with_fr(proof.some_selectors_at_z[i]);
        }
        transcript.update_with_fr(proof.table_at_z);

        //add evaluations zw
        transcript.update_with_fr(proof.wire0_at_z_omega);
        transcript.update_with_fr(proof.grand_product_at_z_omega);
        transcript.update_with_fr(proof.sorted_lookup_at_z_omega);
        transcript.update_with_fr(proof.grand_product_lookup_at_z_omega);
        transcript.update_with_fr(proof.table_at_z_omega);
        transcript.update_with_fr(proof.wire1_at_z_omega);
        transcript.update_with_fr(proof.wire2_at_z_omega);
        transcript.update_with_fr(proof.wire3_at_z_omega);
        transcript.update_with_fr(proof.z_substring_at_z_omega);

        state.v = transcript.get_challenge();

        //add Wz, Wzw
        transcript.update_with_g1(proof.opening_at_z_proof);
        transcript.update_with_g1(proof.opening_at_z_omega_proof);
        state.u = transcript.get_challenge();

        return (true, return_zeta_pow_n);
    }

    // This verifier is for a PLONK with a state width 5
    /**
     * A plonk verifier does two kinds of verifications:
     * 1. target identity holds in Fr, handled by `verify_initial`
     * 2. polynomial commitment openings are correct, handled by `verify_commitments`
     */
    function verify(
        Proof memory proof,
        VerificationKey memory vk,
        bytes32 vkhash
    ) internal view returns (bool) {
        PartialVerifierState memory state;

        (
            bool valid,
            PairingsBn254.Fr memory return_zeta_pow_n
        ) = verify_initial(state, proof, vk, vkhash);

        if (valid == false) {
            return false;
        }

        valid = verify_commitments(return_zeta_pow_n, state, proof, vk);

        return valid;
    }
}

contract SingleVerifierWithDeserialize is
    Plonk4SingleVerifierWithAccessToDNext
{
    uint256 constant SERIALIZED_PROOF_LENGTH = 0;

    // first register srshash
    function srshash_init(uint256 srshash_init) public returns (bool) {
        srshash = bytes32(srshash_init);
        return true;
    }

    // then register vkdata
    function vkhash_init(
        uint64 string_length,
        uint64 num_inputs,
        uint128 domain_size,
        uint256[] memory vkdata
    ) public returns (bool) {
        if (string_length == 1024) {
            vk1024hash = sha256(
                abi.encodePacked(num_inputs, domain_size, vkdata)
            );
        } else if (string_length == 2048) {
            vk2048hash = sha256(
                abi.encodePacked(num_inputs, domain_size, vkdata)
            );
        } else {
            return false;
        }

        return true;
    }

    function multy_verify1024(
        uint64 num_inputs,
        uint128 domain_size,
        uint256[] memory vkdata,
        uint256[] memory public_inputs,
        uint256[] memory serialized_proof
    ) public returns (bool) {
        console.log("1024");
        bytes32 vkhash = sha256(
            abi.encodePacked(num_inputs, domain_size, vkdata)
        );
        // console.logBytes32( vkhash );
        assert(vk1024hash == vkhash);

        VerificationKey memory vk;
        vk.domain_size = domain_size;
        vk.num_inputs = num_inputs;

        vk.omega = PairingsBn254.new_fr(vkdata[0]);

        uint256 j = 1;
        for (uint256 i = 0; i < STATE_WIDTH + 3 + 3; i++) {
            vk.selector_commitments[i] = PairingsBn254.new_g1_checked(
                vkdata[j],
                vkdata[j + 1]
            );
            j += 2;
        }
        for (uint256 i = 0; i < STATE_WIDTH; i++) {
            vk.permutation_commitments[i] = PairingsBn254.new_g1_checked(
                vkdata[j],
                vkdata[j + 1]
            );
            j += 2;
        }
        for (uint256 i = 0; i < STATE_WIDTH + 1; i++) {
            vk.tables_commitments[i] = PairingsBn254.new_g1_checked(
                vkdata[j],
                vkdata[j + 1]
            );
            j += 2;
        }
        // q_substring0 q_substring_r0 q_pubmatch
        for (uint256 i = 0; i < 3; i++) {
            vk.selector_commitments[STATE_WIDTH + 3 + 3 + i] = PairingsBn254
                .new_g1_checked(vkdata[j], vkdata[j + 1]);
            j += 2;
        }

        uint256[2] memory tmpx;
        uint256[2] memory tmpy;

        tmpx[1] = vkdata[j];
        j += 1;
        tmpx[0] = vkdata[j];
        j += 1;
        tmpy[1] = vkdata[j];
        j += 1;
        tmpy[0] = vkdata[j];
        j += 1;
        vk.g2_x = PairingsBn254.new_g2(tmpx, tmpy);

        Proof memory proof = deserialize_proof(public_inputs, serialized_proof);

        PartialVerifierState memory state;

        (bool res, PairingsBn254.Fr memory return_zeta_pow_n) = verify_initial(
            state,
            proof,
            vk,
            vkhash
        );
        if (res == false) {
            return false;
        }
        // return verify(proof, vk);
        res = verify_commitments(return_zeta_pow_n, state, proof, vk);
        console.log("all finish 1024");
        console.log(res);
        return res;
    }

    function multy_verify2048(
        uint64 num_inputs,
        uint128 domain_size,
        uint256[] memory vkdata,
        uint256[] memory public_inputs,
        uint256[] memory serialized_proof
    ) public returns (bool) {
        bytes32 vkhash = sha256(
            abi.encodePacked(num_inputs, domain_size, vkdata)
        );
        // console.logBytes32( vkhash );
        assert(vk2048hash == vkhash);

        VerificationKey memory vk;
        vk.domain_size = domain_size;
        vk.num_inputs = num_inputs;

        vk.omega = PairingsBn254.new_fr(vkdata[0]);

        uint256 j = 1;
        for (uint256 i = 0; i < STATE_WIDTH + 3 + 3; i++) {
            vk.selector_commitments[i] = PairingsBn254.new_g1_checked(
                vkdata[j],
                vkdata[j + 1]
            );
            j += 2;
        }
        for (uint256 i = 0; i < STATE_WIDTH; i++) {
            vk.permutation_commitments[i] = PairingsBn254.new_g1_checked(
                vkdata[j],
                vkdata[j + 1]
            );
            j += 2;
        }
        for (uint256 i = 0; i < STATE_WIDTH + 1; i++) {
            vk.tables_commitments[i] = PairingsBn254.new_g1_checked(
                vkdata[j],
                vkdata[j + 1]
            );
            j += 2;
        }
        // q_substring0 q_substring_r0 q_pubmatch
        for (uint256 i = 0; i < 3; i++) {
            vk.selector_commitments[STATE_WIDTH + 3 + 3 + i] = PairingsBn254
                .new_g1_checked(vkdata[j], vkdata[j + 1]);
            j += 2;
        }

        uint256[2] memory tmpx;
        uint256[2] memory tmpy;

        tmpx[1] = vkdata[j];
        j += 1;
        tmpx[0] = vkdata[j];
        j += 1;
        tmpy[1] = vkdata[j];
        j += 1;
        tmpy[0] = vkdata[j];
        j += 1;
        vk.g2_x = PairingsBn254.new_g2(tmpx, tmpy);

        Proof memory proof = deserialize_proof(public_inputs, serialized_proof);

        PartialVerifierState memory state;

        (bool res, PairingsBn254.Fr memory return_zeta_pow_n) = verify_initial(
            state,
            proof,
            vk,
            vkhash
        );
        if (res == false) {
            return false;
        }
        // return verify(proof, vk);
        res = verify_commitments(return_zeta_pow_n, state, proof, vk);
        console.log("all finish 2048");
        console.log(res);
        return res;
    }

    function deserialize_proof(
        uint256[] memory public_inputs,
        uint256[] memory serialized_proof
    ) internal pure returns (Proof memory proof) {
        // require(serialized_proof.length == SERIALIZED_PROOF_LENGTH);
        proof.input_values = new uint256[](public_inputs.length);
        for (uint256 i = 0; i < public_inputs.length; i++) {
            proof.input_values[i] = public_inputs[i];
        }

        //witness 0123...
        uint256 j = 0;
        for (uint256 i = 0; i < STATE_WIDTH; i++) {
            proof.wire_commitments[i] = PairingsBn254.new_g1_checked(
                serialized_proof[j],
                serialized_proof[j + 1]
            );
            j += 2;
        }
        //s
        proof.sorted_lookup_commitment = PairingsBn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j + 1]
        );
        j += 2;
        //z
        proof.grand_product_commitment = PairingsBn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j + 1]
        );
        j += 2;
        //zlookup
        proof.grand_product_lookup_commitment = PairingsBn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j + 1]
        );
        j += 2;
        //z_substring
        proof.z_substring_commitment = PairingsBn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j + 1]
        );
        j += 2;
        //t123...
        for (uint256 i = 0; i < STATE_WIDTH; i++) {
            proof.quotient_poly_commitments[i] = PairingsBn254.new_g1_checked(
                serialized_proof[j],
                serialized_proof[j + 1]
            );
            j += 2;
        }

        //t(z)
        proof.quotient_polynomial_at_z = PairingsBn254.new_fr(
            serialized_proof[j]
        );
        j += 1;
        //r(z)
        proof.linearization_polynomial_at_z = PairingsBn254.new_fr(
            serialized_proof[j]
        );
        j += 1;
        //`w_0(z)`, `w_1(z)`, `w_2(z)`...
        for (uint256 i = 0; i < STATE_WIDTH; i++) {
            proof.wire_values_at_z[i] = PairingsBn254.new_fr(
                serialized_proof[j]
            );
            j += 1;
        }
        //`sigma_0(z)`, `sigma_1(z)`, `sigma_2(z)`...
        for (uint256 i = 0; i < STATE_WIDTH - 1; i++) {
            proof.permutation_polynomials_at_z[i] = PairingsBn254.new_fr(
                serialized_proof[j]
            );
            j += 1;
        }
        //`q_arith(z)`, `q_table(z)`, `q_lookup(z)`
        for (uint256 i = 0; i < 3; i++) {
            proof.some_selectors_at_z[i] = PairingsBn254.new_fr(
                serialized_proof[j]
            );
            j += 1;
        }
        // `table(z)`
        proof.table_at_z = PairingsBn254.new_fr(serialized_proof[j]);
        j += 1;

        //w0(zw)
        proof.wire0_at_z_omega = PairingsBn254.new_fr(serialized_proof[j]);
        j += 1;
        //z(zw)
        proof.grand_product_at_z_omega = PairingsBn254.new_fr(
            serialized_proof[j]
        );
        j += 1;
        //s(zw)
        proof.sorted_lookup_at_z_omega = PairingsBn254.new_fr(
            serialized_proof[j]
        );
        j += 1;
        //zlookup(zw)
        proof.grand_product_lookup_at_z_omega = PairingsBn254.new_fr(
            serialized_proof[j]
        );
        j += 1;
        //table(zw)
        proof.table_at_z_omega = PairingsBn254.new_fr(serialized_proof[j]);
        j += 1;
        //w1(zw)
        proof.wire1_at_z_omega = PairingsBn254.new_fr(serialized_proof[j]);
        j += 1;
        //w2(zw)
        proof.wire2_at_z_omega = PairingsBn254.new_fr(serialized_proof[j]);
        j += 1;
        //w3(zw)
        proof.wire3_at_z_omega = PairingsBn254.new_fr(serialized_proof[j]);
        j += 1;
        //z_substring(zw)
        proof.z_substring_at_z_omega = PairingsBn254.new_fr(
            serialized_proof[j]
        );
        j += 1;

        proof.opening_at_z_proof = PairingsBn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j + 1]
        );
        j += 2;

        proof.opening_at_z_omega_proof = PairingsBn254.new_g1_checked(
            serialized_proof[j],
            serialized_proof[j + 1]
        );
    }
}
