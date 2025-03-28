// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
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
        require(token != address(0), "MetaTx: token is zero address");
        
        uint256 currentNonce = nonces[owner]++;
        
        bytes32 structHash = keccak256(
            abi.encode(
                REVOKE_TYPEHASH,
                owner,
                spender,
                token,
                currentNonce,
                deadline
            )
        );
        
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, signature);
        
        require(signer != address(0), "MetaTx: zero address");
        require(signer == owner, "MetaTx: invalid signature");
        
        (bool success, bytes memory data) = token.call(
            abi.encodeWithSelector(
                IERC20.approve.selector,
                spender,
                0
            )
        );
        require(success && (data.length == 0 || abi.decode(data, (bool))), "MetaTx: approve failed");
    }

    function isContract(address addr) internal view returns (bool) {
        uint32 size;
        assembly {
            size := extcodesize(addr)
        }
        return (size > 0);
    }
}
