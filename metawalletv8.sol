// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/Create2.sol";

contract MetaWalletV8 {
    using ECDSA for bytes32;

    address public owner;
    bytes public userWalletBytecode;

    mapping(address => bool) public relayerWhitelist;
    mapping(address => uint256) public nonces;
    mapping(address => bool) public isDeployed;

    // EIP-712 constants
    bytes32 public constant META_TX_TYPEHASH = keccak256("MetaTransaction(address user,address target,bytes data,uint256 value,uint256 fee,uint256 nonce)");
    bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public immutable DOMAIN_SEPARATOR;

    string public constant NAME = "MetaWallet";
    string public constant VERSION = "8";

    event WalletDeployed(address indexed user, address wallet);
    event MetaTransactionExecuted(address indexed user, address target, uint256 value, bytes data, uint256 fee);
    event RelayerAdded(address relayer);
    event RelayerRemoved(address relayer);

    constructor() {
        owner = msg.sender;
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256(bytes(NAME)),
            keccak256(bytes(VERSION)),
            block.chainid,
            address(this)
        ));
        userWalletBytecode = type(UserWalletV8).creationCode;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    function computeWalletAddress(address user) public view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(user));
        bytes memory bytecode = abi.encodePacked(userWalletBytecode, abi.encode(user));
        return Create2.computeAddress(salt, keccak256(bytecode));
    }

    function deployWallet(address user) external {
        require(!isDeployed[user], "Already deployed");
        bytes32 salt = keccak256(abi.encodePacked(user));
        bytes memory bytecode = abi.encodePacked(userWalletBytecode, abi.encode(user));
        address wallet = Create2.deploy(0, salt, bytecode);
        isDeployed[user] = true;
        emit WalletDeployed(user, wallet);
    }

    function executeMetaTransaction(
        address user,
        address target,
        bytes calldata data,
        uint256 value,
        uint256 fee,
        uint256 nonce,
        bytes calldata signature
    ) external {
        require(relayerWhitelist[msg.sender], "Not authorized");
        require(nonce == nonces[user]++, "Invalid nonce");

        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            keccak256(abi.encode(
                META_TX_TYPEHASH,
                user,
                target,
                keccak256(data),
                value,
                fee,
                nonce
            ))
        ));

        require(digest.recover(signature) == user, "Invalid signature");

        address wallet = computeWalletAddress(user);
        require(wallet.code.length > 0, "Wallet not deployed");

        // Execute user transaction
        (bool success, ) = wallet.call(abi.encodeWithSignature(
            "execute(address,bytes,uint256,uint256,address)",
            target,
            data,
            value,
            fee,
            msg.sender
        ));
        require(success, "Execution failed");

        emit MetaTransactionExecuted(user, target, value, data, fee);
    }

    function addRelayer(address relayer) external onlyOwner {
        relayerWhitelist[relayer] = true;
        emit RelayerAdded(relayer);
    }

    function removeRelayer(address relayer) external onlyOwner {
        relayerWhitelist[relayer] = false;
        emit RelayerRemoved(relayer);
    }
}

// User Wallet V8
contract UserWalletV8 {
    address public owner;

    event Received(address sender, uint256 amount);
    event Withdrawn(address to, uint256 amount);
    event ERC20Withdrawn(address token, address to, uint256 amount);
    event BatchExecuted(uint256 successCount);

    constructor(address _owner) {
        owner = _owner;
    }

    receive() external payable {
        emit Received(msg.sender, msg.value);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    // Execute with fee payment
    function execute(
        address target,
        bytes memory data,
        uint256 value,
        uint256 fee,
        address relayer
    ) external onlyOwner returns (bool) {
        require(address(this).balance >= value + fee, "Insufficient ETH balance");

        // Execute user request
        (bool success, ) = target.call{value: value}(data);
        require(success, "Call failed");

        // Pay relayer fee
        (bool feeSuccess, ) = payable(relayer).call{value: fee}("");
        require(feeSuccess, "Fee payment failed");

        return true;
    }

    // Simple withdraw ETH
    function withdrawTo(address payable recipient, uint256 amount) external onlyOwner {
        require(address(this).balance >= amount, "Insufficient ETH");
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
        emit Withdrawn(recipient, amount);
    }

    // Withdraw ERC20 token
    function withdrawERC20To(address token, address recipient, uint256 amount) external onlyOwner {
        require(IERC20(token).balanceOf(address(this)) >= amount, "Insufficient token balance");
        bool success = IERC20(token).transfer(recipient, amount);
        require(success, "Transfer failed");
        emit ERC20Withdrawn(token, recipient, amount);
    }

    // Owner withdraw all
    function withdraw(uint256 amount) external onlyOwner {
        require(address(this).balance >= amount, "Insufficient ETH");
        payable(owner).transfer(amount);
        emit Withdrawn(owner, amount);
    }

    // Batch call multiple transactions
    function batchExecute(address[] calldata targets, bytes[] calldata datas, uint256[] calldata values) external onlyOwner returns (uint256) {
        require(targets.length == datas.length && datas.length == values.length, "Array mismatch");

        uint256 successCount = 0;
        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, ) = targets[i].call{value: values[i]}(datas[i]);
            if (success) {
                successCount++;
            }
        }
        emit BatchExecuted(successCount);
        return successCount;
    }
}
