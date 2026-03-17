// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
// VulnerableVault.sol
// Minimal ERC4626-style vault WITHOUT virtual shares protection
// Purpose: Demonstrate inflation attack surface
// ============================================================

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

// --- Underlying asset token (simple mintable ERC20) ---
contract MockToken is ERC20 {
    constructor() ERC20("Mock Token", "MTK") {}

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

// --- Vulnerable Vault (raw ERC4626 math, no virtual shares) ---
contract VulnerableVault is ERC20 {
    IERC20 public immutable asset;

    constructor(address _asset) ERC20("Vault Share", "vMTK") {
        asset = IERC20(_asset);
    }

    // --------------------------------------------------------
    // Core: shares = assets * totalSupply / totalAssets
    // When totalSupply == 0, 1:1 bootstrap
    // --------------------------------------------------------
    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = _convertToShares(assets);
        require(shares > 0, "VulnerableVault: zero shares");

        asset.transferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);
    }

    function redeem(uint256 shares, address receiver) external returns (uint256 assets) {
        assets = _convertToAssets(shares);
        _burn(msg.sender, shares);
        asset.transfer(receiver, assets);
    }

    function totalAssets() public view returns (uint256) {
        // Relies on raw balanceOf — this is exactly what makes donation attacks work
        return asset.balanceOf(address(this));
    }

    function _convertToShares(uint256 assets) internal view returns (uint256) {
        uint256 supply = totalSupply();
        // When vault is empty: 1:1
        // Otherwise: shares = assets * supply / totalAssets
        return supply == 0 ? assets : (assets * supply) / totalAssets();
    }

    function _convertToAssets(uint256 shares) internal view returns (uint256) {
        uint256 supply = totalSupply();
        return supply == 0 ? shares : (shares * totalAssets()) / supply;
    }

    // View helpers
    function previewDeposit(uint256 assets) external view returns (uint256) {
        return _convertToShares(assets);
    }

    function previewRedeem(uint256 shares) external view returns (uint256) {
        return _convertToAssets(shares);
    }

    function sharePriceE18() external view returns (uint256) {
        uint256 supply = totalSupply();
        if (supply == 0) return 1e18;
        return (totalAssets() * 1e18) / supply;
    }
}
