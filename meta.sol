// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IERC20 {
    function transfer(address recipient, uint256 amount) external returns (bool);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract MetaWalletV2 {
    address public owner;
    mapping(address => uint256) public balances;
    mapping(address => uint256) public nonces;
    mapping(bytes32 => bool) public usedHashes;
    mapping(address => bool) public relayerWhitelist;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event MetaTransactionExecuted(address indexed user, address target, bytes data);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Not enough balance");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
        emit Withdrawn(msg.sender, amount);
    }

    // ========== Utilities ==========
    function getMessageHash(
        address user,
        address target,
        bytes memory data,
        uint256 nonce
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, target, data, nonce));
    }

    function recoverSigner(
        bytes32 messageHash,
        bytes memory signature
    ) public pure returns (address) {
        bytes32 ethHash = prefixed(messageHash);
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);
        return ecrecover(ethHash, v, r, s);
    }

    function prefixed(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function splitSignature(
        bytes memory sig
    ) internal pure returns (uint8, bytes32, bytes32) {
        require(sig.length == 65, "Invalid signature length");
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

    // ========== MetaTx Core ==========
    function executeMetaTransaction(
        address user,
        address target,
        bytes calldata data,
        uint256 nonce,
        bytes calldata signature
    ) external {
        require(relayerWhitelist[msg.sender], "Not authorized relayer");
        require(nonce == nonces[user], "Invalid nonce");

        bytes32 hash = getMessageHash(user, target, data, nonce);
        require(!usedHashes[hash], "Replay attack");
        require(recoverSigner(hash, signature) == user, "Invalid signature");

        usedHashes[hash] = true;
        nonces[user]++;

        (bool success, ) = target.call(data);
        require(success, "Call failed");

        emit MetaTransactionExecuted(user, target, data);
    }

    // ========== Meta Functions ==========
    function metaRevoke(
        address user,
        address token,
        address spender,
        uint256 nonce,
        bytes calldata signature
    ) external {
        bytes memory data = abi.encodeWithSelector(
            IERC20.approve.selector,
            spender,
            0
        );
        executeMetaTransaction(user, token, data, nonce, signature);
    }

    function metaSendToken(
        address user,
        address token,
        address to,
        uint256 amount,
        uint256 nonce,
        bytes calldata signature
    ) external {
        bytes memory data = abi.encodeWithSelector(
            IERC20.transfer.selector,
            to,
            amount
        );
        executeMetaTransaction(user, token, data, nonce, signature);
    }

    function metaSendETH(
        address user,
        address to,
        uint256 amount,
        uint256 nonce,
        bytes calldata signature
    ) external {
        require(relayerWhitelist[msg.sender], "Only relayer");
        require(nonce == nonces[user], "Invalid nonce");

        bytes32 hash = getMessageHash(user, to, abi.encodePacked(amount), nonce);
        require(!usedHashes[hash], "Replay");
        require(recoverSigner(hash, signature) == user, "Invalid signature");

        usedHashes[hash] = true;
        nonces[user]++;

        payable(to).transfer(amount);
        emit MetaTransactionExecuted(user, to, abi.encodePacked(amount));
    }

    // ========== Relayer Controls ==========
    function addRelayer(address relayer) external onlyOwner {
        relayerWhitelist[relayer] = true;
    }

    function removeRelayer(address relayer) external onlyOwner {
        relayerWhitelist[relayer] = false;
    }
}
