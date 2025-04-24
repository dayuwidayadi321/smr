// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address recipient, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract UserWallet {
    address public owner;
    constructor(address _owner) {
        owner = _owner;
    }
    receive() external payable {}
    
    function withdraw(uint256 amount) external {
        require(msg.sender == owner, "Only owner");
        payable(owner).transfer(amount);
    }
    
    function execute(address target, bytes memory data) external returns (bool) {
        require(msg.sender == owner, "Only owner");
        (bool success, ) = target.call(data);
        return success;
    }
    
    // Fungsi baru untuk membayar gas fee dari sub-wallet
    function payGasAndExecute(
        address target,
        bytes memory data,
        address relayer,
        uint256 gasFee
    ) external returns (bool) {
        require(msg.sender == owner, "Only owner");
        
        // Pastikan ada cukup ETH untuk gas fee
        require(address(this).balance >= gasFee, "Insufficient ETH for gas");
        
        // Bayar gas fee ke relayer
        payable(relayer).transfer(gasFee);
        
        // Eksekusi operasi utama
        (bool success, ) = target.call(data);
        return success;
    }
}

contract MetaWalletV2 {
    address public owner;
    mapping(address => address) public userWallets;
    mapping(address => bool) public relayerWhitelist;
    mapping(bytes32 => bool) public usedHashes;
    mapping(address => uint256) public nonces;

    event WalletCreated(address indexed user, address wallet);
    event WalletUpgraded(address indexed user, address oldWallet, address newWallet);
    event Deposited(address indexed user, address wallet, uint256 amount);
    event MetaTransactionExecuted(address indexed user, address target, bytes data, uint256 gasFee);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier onlyWalletOwner(address user) {
        require(msg.sender == user, "Only wallet owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // Deposit dan buat wallet jika belum ada
    function deposit() external payable {
        if (userWallets[msg.sender] == address(0)) {
            _createWallet(msg.sender);
        }
        (bool sent, ) = userWallets[msg.sender].call{value: msg.value}("");
        require(sent, "Transfer failed");
        emit Deposited(msg.sender, userWallets[msg.sender], msg.value);
    }

    // Fungsi upgrade wallet (migrasi dana otomatis)
    function upgradeWallet() external onlyWalletOwner(msg.sender) {
        address oldWallet = userWallets[msg.sender];
        require(oldWallet != address(0), "No existing wallet");

        _createWallet(msg.sender);
        address newWallet = userWallets[msg.sender];

        uint256 balance = address(oldWallet).balance;
        if (balance > 0) {
            (bool success, ) = oldWallet.call(
                abi.encodeWithSignature(
                    "withdraw(uint256)",
                    balance
                )
            );
            require(success, "Withdraw from old wallet failed");
            (bool sent, ) = newWallet.call{value: balance}("");
            require(sent, "Transfer to new wallet failed");
        }

        emit WalletUpgraded(msg.sender, oldWallet, newWallet);
    }

    function _createWallet(address user) internal {
        UserWallet wallet = new UserWallet(user);
        userWallets[user] = address(wallet);
        emit WalletCreated(user, address(wallet));
    }

    // Eksekusi meta-transaksi dengan pembayaran gas dari sub-wallet
    function executeMetaTransaction(
        address user,
        address target,
        bytes memory data,
        uint256 nonce,
        bytes calldata signature,
        uint256 gasFee
    ) external {
        require(relayerWhitelist[msg.sender], "Not authorized relayer");
        require(nonce == nonces[user]++, "Invalid nonce");

        bytes32 hash = keccak256(abi.encodePacked(user, target, data, nonce, gasFee));
        require(!usedHashes[hash], "Replay attack");
        require(recoverSigner(hash, signature) == user, "Invalid signature");

        usedHashes[hash] = true;
        
        address wallet = userWallets[user];
        require(wallet != address(0), "No wallet found");
        
        // Panggil payGasAndExecute di sub-wallet
        (bool success, ) = wallet.call(
            abi.encodeWithSignature(
                "payGasAndExecute(address,bytes,address,uint256)",
                target,
                data,
                msg.sender, // relayer address
                gasFee
            )
        );
        require(success, "Call failed");
        emit MetaTransactionExecuted(user, target, data, gasFee);
    }

    // Utility functions
    function recoverSigner(bytes32 hash, bytes memory sig) public pure returns (address) {
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(sig);
        return ecrecover(hash, v, r, s);
    }

    function splitSignature(bytes memory sig) internal pure returns (uint8, bytes32, bytes32) {
        require(sig.length == 65, "Invalid signature");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return (v, r, s);
    }

    // Owner controls
    function addRelayer(address relayer) external onlyOwner {
        relayerWhitelist[relayer] = true;
    }
    
    // Fungsi untuk mengecek saldo sub-wallet
    function getWalletBalance(address user) external view returns (uint256) {
        address wallet = userWallets[user];
        if (wallet == address(0)) return 0;
        return wallet.balance;
    }
}
