// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol"; // Added for ERC20 support

contract MetaWalletV4 {
    using ECDSA for bytes32;
    
    address public owner;
    mapping(address => address) public userWallets;
    mapping(address => bool) public relayerWhitelist;
    mapping(address => uint256) public nonces;

    // EIP-712 Constants
    bytes32 public constant META_TRANSACTION_TYPEHASH = 
        keccak256("MetaTransaction(address user,address target,bytes data,uint256 nonce)");
    bytes32 public constant DOMAIN_TYPEHASH = 
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public immutable DOMAIN_SEPARATOR;
    string public constant CONTRACT_NAME = "MetaWallet";
    string public constant CONTRACT_VERSION = "1";

    event WalletCreated(address indexed user, address wallet);
    event MetaTransactionExecuted(address indexed user, address target, bytes data);
    event Withdrawal(address indexed wallet, address indexed to, uint256 amount); // New event

    constructor() {
        owner = msg.sender;
        DOMAIN_SEPARATOR = keccak256(abi.encode(
            DOMAIN_TYPEHASH,
            keccak256(bytes(CONTRACT_NAME)),
            keccak256(bytes(CONTRACT_VERSION)),
            block.chainid,
            address(this)
        ));
    }

    function createWallet() external {
        if (userWallets[msg.sender] == address(0)) {
            userWallets[msg.sender] = address(new UserWallet(msg.sender));
            emit WalletCreated(msg.sender, userWallets[msg.sender]);
        }
    }

    function executeMetaTransaction(
        address user,
        address target,
        bytes calldata data,
        uint256 nonce,
        bytes calldata signature
    ) external {
        require(relayerWhitelist[msg.sender], "Not authorized relayer");
        require(nonce == nonces[user]++, "Invalid nonce");

        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            DOMAIN_SEPARATOR,
            keccak256(abi.encode(
                META_TRANSACTION_TYPEHASH,
                user,
                target,
                keccak256(data),
                nonce
            ))
        ));
        
        require(digest.recover(signature) == user, "Invalid signature");
        
        address wallet = userWallets[user];
        require(wallet != address(0), "No wallet found");
        
        (bool success, ) = wallet.call(abi.encodeWithSignature(
            "execute(address,bytes)",
            target,
            data
        ));
        require(success, "Execution failed");
        
        emit MetaTransactionExecuted(user, target, data);
    }

    function addRelayer(address relayer) external {
        require(msg.sender == owner, "Only owner");
        relayerWhitelist[relayer] = true;
    }
}

contract UserWallet {
    address public owner;
    
    event Withdrawn(address indexed to, uint256 amount); // New event
    event ERC20Withdrawn(address indexed token, address indexed to, uint256 amount); // New event

    constructor(address _owner) {
        owner = _owner;
    }
    
    receive() external payable {} // Added to receive ETH

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    // Existing execute function
    function execute(address target, bytes memory data) external onlyOwner returns (bool) {
        (bool success, ) = target.call(data);
        return success;
    }

    // New: Withdraw ETH to any address
    function withdrawTo(address payable recipient, uint256 amount) external onlyOwner {
        require(recipient != address(0), "Invalid recipient address");
        require(address(this).balance >= amount, "Insufficient balance");
        
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit Withdrawn(recipient, amount);
    }

    // New: Withdraw ERC20 tokens
    function withdrawERC20To(address token, address recipient, uint256 amount) external onlyOwner {
        require(recipient != address(0), "Invalid recipient address");
        require(IERC20(token).balanceOf(address(this)) >= amount, "Insufficient token balance");
        
        bool success = IERC20(token).transfer(recipient, amount);
        require(success, "Token transfer failed");
        
        emit ERC20Withdrawn(token, recipient, amount);
    }

    // Existing withdraw function (for backward compatibility)
    function withdraw(uint256 amount) external onlyOwner {
        require(address(this).balance >= amount, "Insufficient balance");
        payable(owner).transfer(amount);
        emit Withdrawn(owner, amount);
    }
}
