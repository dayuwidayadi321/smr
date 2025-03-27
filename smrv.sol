
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract MetaTxReceiver is EIP712 {
    bytes32 public constant REVOKE_TYPEHASH = keccak256(
        "RevokeApproval(address owner,address spender,address token,uint256 nonce,uint256 deadline)"
    );
    
    mapping(address => uint256) public nonces;
    
    constructor() EIP712("MetaTxApp", "1") {}
    
    function executeRevoke(
        address owner,
        address spender,
        address token,
        uint256 deadline,
        bytes calldata signature
    ) external {
        require(block.timestamp <= deadline, "MetaTx: expired");
        
        bytes32 structHash = keccak256(
            abi.encode(
                REVOKE_TYPEHASH,
                owner,
                spender,
                token,
                nonces[owner]++,
                deadline
            )
        );
        
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);
        
        require(signer == owner, "MetaTx: invalid signature");
        require(signer != address(0), "MetaTx: zero address");
        
        // Eksekusi revoke
        IERC20(token).approve(spender, 0);
    }
}
