// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/utils/Create2.sol";

contract MetaWalletV6 {
    using ECDSA for bytes32;

    address public owner;
    bytes public userWalletBytecode;

    mapping(address => bool) public relayerWhitelist;
    mapping(address => uint256) public nonces;
    mapping(address => bool) public isDeployed;

    // EIP-712 Constants
    bytes32 public constant META_TX_TYPEHASH = keccak256("MetaTransaction(address user,address target,bytes data,uint256 nonce)");
    bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public immutable DOMAIN_SEPARATOR;

    string public constant NAME = "MetaWallet";
    string public constant VERSION = "6";

    event WalletDeployed(address indexed user, address wallet);
    event MetaTransactionExecuted(address indexed user, address target, bytes data);
    event RelayerAdded(address relayer);

    constructor() {
        owner = msg.sender;
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256(bytes(NAME)),
            keccak256(bytes(VERSION)),
            block.chainid,
            address(this)
        ));
        userWalletBytecode = type(UserWallet).creationCode;
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
                nonce
            ))
        ));

        require(digest.recover(signature) == user, "Invalid signature");

        address wallet = computeWalletAddress(user);
        require(wallet.code.length > 0, "Wallet not deployed");

        (bool success, ) = wallet.call(abi.encodeWithSignature("execute(address,bytes)", target, data));
        require(success, "Execution failed");

        emit MetaTransactionExecuted(user, target, data);
    }

    function addRelayer(address relayer) external onlyOwner {
        relayerWhitelist[relayer] = true;
        emit RelayerAdded(relayer);
    }
}

contract UserWallet {
    address public owner;

    event Received(address sender, uint256 amount);
    event Withdrawn(address to, uint256 amount);
    event ERC20Withdrawn(address token, address to, uint256 amount);

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

    function execute(address target, bytes memory data) external onlyOwner returns (bool) {
        (bool success, ) = target.call(data);
        return success;
    }

    function withdrawTo(address payable recipient, uint256 amount) external onlyOwner {
        require(address(this).balance >= amount, "Insufficient ETH");
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
        emit Withdrawn(recipient, amount);
    }

    function withdrawERC20To(address token, address recipient, uint256 amount) external onlyOwner {
        require(IERC20(token).balanceOf(address(this)) >= amount, "Insufficient token balance");
        bool success = IERC20(token).transfer(recipient, amount);
        require(success, "Transfer failed");
        emit ERC20Withdrawn(token, recipient, amount);
    }

    function withdraw(uint256 amount) external onlyOwner {
        require(address(this).balance >= amount, "Insufficient ETH");
        payable(owner).transfer(amount);
        emit Withdrawn(owner, amount);
    }
}
