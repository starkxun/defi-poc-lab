// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ============================================================
// SafeVault.sol
// ERC4626-style vault WITH virtual shares (OpenZeppelin pattern)
// Purpose: Show how virtual offset defeats inflation attack
// ============================================================

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "openzeppelin-contracts/contracts/token/ERC20/IERC20.sol";

contract SafeVault is ERC20 {
    IERC20 public immutable asset;

    // Virtual offset: makes it extremely expensive to manipulate share price
    // OpenZeppelin uses 10 ** _decimalsOffset() where decimalsOffset = 0 by default
    // Here we use a larger offset for dramatic demonstration
    uint256 private constant VIRTUAL_SHARES = 1e3;
    uint256 private constant VIRTUAL_ASSETS = 1;

    constructor(address _asset) ERC20("Safe Vault Share", "svMTK") {
        asset = IERC20(_asset);
    }

    function deposit(uint256 assets, address receiver) external returns (uint256 shares) {
        shares = _convertToShares(assets);
        require(shares > 0, "SafeVault: zero shares");

        asset.transferFrom(msg.sender, address(this), assets);
        _mint(receiver, shares);
    }

    function redeem(uint256 shares, address receiver) external returns (uint256 assets) {
        assets = _convertToAssets(shares);
        _burn(msg.sender, shares);
        asset.transfer(receiver, assets);
    }

    function totalAssets() public view returns (uint256) {
        return asset.balanceOf(address(this));
    }

    // Key difference: +VIRTUAL_SHARES and +VIRTUAL_ASSETS in formula
    // shares = assets * (supply + VIRTUAL_SHARES) / (totalAssets + VIRTUAL_ASSETS)
    function _convertToShares(uint256 assets) internal view returns (uint256) {
        return (assets * (totalSupply() + VIRTUAL_SHARES)) / (totalAssets() + VIRTUAL_ASSETS);
    }

    function _convertToAssets(uint256 shares) internal view returns (uint256) {
        return (shares * (totalAssets() + VIRTUAL_ASSETS)) / (totalSupply() + VIRTUAL_SHARES);
    }

    function previewDeposit(uint256 assets) external view returns (uint256) {
        return _convertToShares(assets);
    }

    function sharePriceE18() external view returns (uint256) {
        return ((totalAssets() + VIRTUAL_ASSETS) * 1e18) / (totalSupply() + VIRTUAL_SHARES);
    }
}
