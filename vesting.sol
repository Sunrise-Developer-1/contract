/**
 *Submitted for verification at Etherscan.io on 2024-05-13
*/

pragma solidity ^0.8.12;

interface IBEP20 {
    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender)
        external
        view
        returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `from` to `to` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool);

    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(
        address indexed owner,
        address indexed spender,
        uint256 value
    );
}
library Strings {
    bytes16 private constant _HEX_SYMBOLS = "0123456789abcdef";

    /**
     * @dev Converts a `uint256` to its ASCII `string` decimal representation.
     */
    function toString(uint256 value) internal pure returns (string memory) {
        // Inspired by OraclizeAPI's implementation - MIT licence
        // https://github.com/oraclize/ethereum-api/blob/b42146b063c7d6ee1358846c198246239e9360e8/oraclizeAPI_0.4.25.sol

        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.
     */
    function toHexString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0x00";
        }
        uint256 temp = value;
        uint256 length = 0;
        while (temp != 0) {
            length++;
            temp >>= 8;
        }
        return toHexString(value, length);
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.
     */
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = _HEX_SYMBOLS[value & 0xf];
            value >>= 4;
        }
        require(value == 0, "Strings: hex length insufficient");
        return string(buffer);
    }
}
library ECDSA {
    enum RecoverError {
        NoError,
        InvalidSignature,
        InvalidSignatureLength,
        InvalidSignatureS,
        InvalidSignatureV
    }

    function _throwError(RecoverError error) private pure {
        if (error == RecoverError.NoError) {
            return; // no error: do nothing
        } else if (error == RecoverError.InvalidSignature) {
            revert("ECDSA: invalid signature");
        } else if (error == RecoverError.InvalidSignatureLength) {
            revert("ECDSA: invalid signature length");
        } else if (error == RecoverError.InvalidSignatureS) {
            revert("ECDSA: invalid signature 's' value");
        } else if (error == RecoverError.InvalidSignatureV) {
            revert("ECDSA: invalid signature 'v' value");
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature` or error string. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     *
     * Documentation for signature generation:
     * - with https://web3js.readthedocs.io/en/v1.3.4/web3-eth-accounts.html#sign[Web3.js]
     * - with https://docs.ethers.io/v5/api/signer/#Signer-signMessage[ethers]
     *
     * _Available since v4.3._
     */
    function tryRecover(bytes32 hash, bytes memory signature)
        internal
        pure
        returns (address, RecoverError)
    {
        // Check the signature length
        // - case 65: r,s,v signature (standard)
        // - case 64: r,vs signature (cf https://eips.ethereum.org/EIPS/eip-2098) _Available since v4.1._
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            return tryRecover(hash, v, r, s);
        } else if (signature.length == 64) {
            bytes32 r;
            bytes32 vs;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            assembly {
                r := mload(add(signature, 0x20))
                vs := mload(add(signature, 0x40))
            }
            return tryRecover(hash, r, vs);
        } else {
            return (address(0), RecoverError.InvalidSignatureLength);
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     */
    function recover(bytes32 hash, bytes memory signature)
        internal
        pure
        returns (address)
    {
        (address recovered, RecoverError error) = tryRecover(hash, signature);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `r` and `vs` short-signature fields separately.
     *
     * See https://eips.ethereum.org/EIPS/eip-2098[EIP-2098 short signatures]
     *
     * _Available since v4.3._
     */
    function tryRecover(
        bytes32 hash,
        bytes32 r,
        bytes32 vs
    ) internal pure returns (address, RecoverError) {
        bytes32 s = vs &
            bytes32(
                0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
            );
        uint8 v = uint8((uint256(vs) >> 255) + 27);
        return tryRecover(hash, v, r, s);
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `r and `vs` short-signature fields separately.
     *
     * _Available since v4.2._
     */
    function recover(
        bytes32 hash,
        bytes32 r,
        bytes32 vs
    ) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, r, vs);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `v`,
     * `r` and `s` signature fields separately.
     *
     * _Available since v4.3._
     */
    function tryRecover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address, RecoverError) {
        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        if (
            uint256(s) >
            0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        ) {
            return (address(0), RecoverError.InvalidSignatureS);
        }
        if (v != 27 && v != 28) {
            return (address(0), RecoverError.InvalidSignatureV);
        }

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return (address(0), RecoverError.InvalidSignature);
        }

        return (signer, RecoverError.NoError);
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function recover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, v, r, s);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Returns an Ethereum Signed Message, created from a `hash`. This
     * produces hash corresponding to the one signed with the
     * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]
     * JSON-RPC method as part of EIP-191.
     *
     * See {recover}.
     */
    function toEthSignedMessageHash(bytes32 hash)
        internal
        pure
        returns (bytes32)
    {
        // 32 is the length in bytes of hash,
        // enforced by the type signature above
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
            );
    }

    /**
     * @dev Returns an Ethereum Signed Message, created from `s`. This
     * produces hash corresponding to the one signed with the
     * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]
     * JSON-RPC method as part of EIP-191.
     *
     * See {recover}.
     */
    function toEthSignedMessageHash(bytes memory s)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encodePacked(
                    "\x19Ethereum Signed Message:\n",
                    Strings.toString(s.length),
                    s
                )
            );
    }
    /**
     * @dev Returns an Ethereum Signed Typed Data, created from a
     * `domainSeparator` and a `structHash`. This produces hash corresponding
     * to the one signed with the
     * https://eips.ethereum.org/EIPS/eip-712[`eth_signTypedData`]
     * JSON-RPC method as part of EIP-712.
     *
     * See {recover}.
     */
    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash)
        internal
        pure
        returns (bytes32)
    {
        return
            keccak256(
                abi.encodePacked("\x19\x01", domainSeparator, structHash)
            );
    }
}
library AddressUpgradeable {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * [IMPORTANT]
     * ====
     * It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     *
     * Among others, `isContract` will return false for the following
     * types of addresses:
     *
     *  - an externally-owned account
     *  - a contract in construction
     *  - an address where a contract will be created
     *  - an address where a contract lived, but was destroyed
     * ====
     *
     * [IMPORTANT]
     * ====
     * You shouldn't rely on `isContract` to protect against flash loan attacks!
     *
     * Preventing calls from contracts is highly discouraged. It breaks composability, breaks support for smart wallets
     * like Gnosis Safe, and does not provide security since it can be circumvented by calling from a contract
     * constructor.
     * ====
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize/address.code.length, which returns 0
        // for contracts in construction, since the code is only stored at the end
        // of the constructor execution.

        return account.code.length > 0;
    }

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }

    /**
     * @dev Performs a Solidity function call using a low level `call`. A
     * plain `call` is an unsafe replacement for a function call: use this
     * function instead.
     *
     * If `target` reverts with a revert reason, it is bubbled up by this
     * function (like regular Solidity function calls).
     *
     * Returns the raw returned data. To convert to the expected return value,
     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].
     *
     * Requirements:
     *
     * - `target` must be a contract.
     * - calling `target` with `data` must not revert.
     *
     * _Available since v3.1._
     */
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, "Address: low-level call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`], but with
     * `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but also transferring `value` wei to `target`.
     *
     * Requirements:
     *
     * - the calling contract must have an ETH balance of at least `value`.
     * - the called Solidity function must be `payable`.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }

    /**
     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but
     * with `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(address(this).balance >= value, "Address: insufficient balance for call");
        (bool success, bytes memory returndata) = target.call{value: value}(data);
        return verifyCallResultFromTarget(target, success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        return functionStaticCall(target, data, "Address: low-level static call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal view returns (bytes memory) {
        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResultFromTarget(target, success, returndata, errorMessage);
    }

    /**
     * @dev Tool to verify that a low level call to smart-contract was successful, and revert (either by bubbling
     * the revert reason or using the provided one) in case of unsuccessful call or if target was not a contract.
     *
     * _Available since v4.8._
     */
    function verifyCallResultFromTarget(
        address target,
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) internal view returns (bytes memory) {
        if (success) {
            if (returndata.length == 0) {
                // only check isContract if the call was successful and the return data is empty
                // otherwise we already know that it was a contract
                require(isContract(target), "Address: call to non-contract");
            }
            return returndata;
        } else {
            _revert(returndata, errorMessage);
        }
    }

    /**
     * @dev Tool to verify that a low level call was successful, and revert if it wasn't, either by bubbling the
     * revert reason or using the provided one.
     *
     * _Available since v4.3._
     */
    function verifyCallResult(
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) internal pure returns (bytes memory) {
        if (success) {
            return returndata;
        } else {
            _revert(returndata, errorMessage);
        }
    }

    function _revert(bytes memory returndata, string memory errorMessage) private pure {
        // Look for revert reason and bubble it up if present
        if (returndata.length > 0) {
            // The easiest way to bubble the revert reason is using memory via assembly
            /// @solidity memory-safe-assembly
            assembly {
                let returndata_size := mload(returndata)
                revert(add(32, returndata), returndata_size)
            }
        } else {
            revert(errorMessage);
        }
    }
}
abstract contract EIP712 {
    /* solhint-disable var-name-mixedcase */
    // Cache the domain separator as an immutable value, but also store the chain id that it corresponds to, in order to
    // invalidate the cached domain separator if the chain id changes.
    bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;
    uint256 private immutable _CACHED_CHAIN_ID;
    address private immutable _CACHED_THIS;

    bytes32 private immutable _HASHED_NAME;
    bytes32 private immutable _HASHED_VERSION;
    bytes32 private immutable _TYPE_HASH;

    /* solhint-enable var-name-mixedcase */

    /**
     * @dev Initializes the domain separator and parameter caches.
     *
     * The meaning of `name` and `version` is specified in
     * https://eips.ethereum.org/EIPS/eip-712#definition-of-domainseparator[EIP 712]:
     *
     * - `name`: the user readable name of the signing domain, i.e. the name of the DApp or the protocol.
     * - `version`: the current major version of the signing domain.
     *
     * NOTE: These parameters cannot be changed except through a xref:learn::upgrading-smart-contracts.adoc[smart
     * contract upgrade].
     */
    constructor(string memory name, string memory version) {
        bytes32 hashedName = keccak256(bytes(name));
        bytes32 hashedVersion = keccak256(bytes(version));
        bytes32 typeHash = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
        _HASHED_NAME = hashedName;
        _HASHED_VERSION = hashedVersion;
        _CACHED_CHAIN_ID = block.chainid;
        _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator(
            typeHash,
            hashedName,
            hashedVersion
        );
        _CACHED_THIS = address(this);
        _TYPE_HASH = typeHash;
    }

    /**
     * @dev Returns the domain separator for the current chain.
     */
    function _domainSeparatorV4() internal view returns (bytes32) {
        if (
            address(this) == _CACHED_THIS && block.chainid == _CACHED_CHAIN_ID
        ) {
            return _CACHED_DOMAIN_SEPARATOR;
        } else {
            return
                _buildDomainSeparator(
                    _TYPE_HASH,
                    _HASHED_NAME,
                    _HASHED_VERSION
                );
        }
    }

    function _buildDomainSeparator(
        bytes32 typeHash,
        bytes32 nameHash,
        bytes32 versionHash
    ) private view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    typeHash,
                    nameHash,
                    versionHash,
                    block.chainid,
                    address(this)
                )
            );
    }

    /**
     * @dev Given an already https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct[hashed struct], this
     * function returns the hash of the fully encoded EIP712 message for this domain.
     *
     * This hash can be used together with {ECDSA-recover} to obtain the signer of a message. For example:
     *
     * ```solidity
     * bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
     *     keccak256("Mail(address to,string contents)"),
     *     mailTo,
     *     keccak256(bytes(mailContents))
     * )));
     * address signer = ECDSA.recover(digest, signature);
     * ```
     */
    function _hashTypedDataV4(bytes32 structHash)
        internal
        view
        virtual
        returns (bytes32)
    {
        return ECDSA.toTypedDataHash(_domainSeparatorV4(), structHash);
    }
}
abstract contract Initializable {
    /**
     * @dev Indicates that the contract has been initialized.
     * @custom:oz-retyped-from bool
     */
    uint8 private _initialized;

    /**
     * @dev Indicates that the contract is in the process of being initialized.
     */
    bool private _initializing;

    /**
     * @dev Triggered when the contract has been initialized or reinitialized.
     */
    event Initialized(uint8 version);

    /**
     * @dev A modifier that defines a protected initializer function that can be invoked at most once. In its scope,
     * `onlyInitializing` functions can be used to initialize parent contracts.
     *
     * Similar to `reinitializer(1)`, except that functions marked with `initializer` can be nested in the context of a
     * constructor.
     *
     * Emits an {Initialized} event.
     */
    modifier initializer() {
        bool isTopLevelCall = !_initializing;
        require(
            (isTopLevelCall && _initialized < 1) || (!AddressUpgradeable.isContract(address(this)) && _initialized == 1),
            "Initializable: contract is already initialized"
        );
        _initialized = 1;
        if (isTopLevelCall) {
            _initializing = true;
        }
        _;
        if (isTopLevelCall) {
            _initializing = false;
            emit Initialized(1);
        }
    }

    /**
     * @dev A modifier that defines a protected reinitializer function that can be invoked at most once, and only if the
     * contract hasn't been initialized to a greater version before. In its scope, `onlyInitializing` functions can be
     * used to initialize parent contracts.
     *
     * A reinitializer may be used after the original initialization step. This is essential to configure modules that
     * are added through upgrades and that require initialization.
     *
     * When `version` is 1, this modifier is similar to `initializer`, except that functions marked with `reinitializer`
     * cannot be nested. If one is invoked in the context of another, execution will revert.
     *
     * Note that versions can jump in increments greater than 1; this implies that if multiple reinitializers coexist in
     * a contract, executing them in the right order is up to the developer or operator.
     *
     * WARNING: setting the version to 255 will prevent any future reinitialization.
     *
     * Emits an {Initialized} event.
     */
    modifier reinitializer(uint8 version) {
        require(!_initializing && _initialized < version, "Initializable: contract is already initialized");
        _initialized = version;
        _initializing = true;
        _;
        _initializing = false;
        emit Initialized(version);
    }

    /**
     * @dev Modifier to protect an initialization function so that it can only be invoked by functions with the
     * {initializer} and {reinitializer} modifiers, directly or indirectly.
     */
    modifier onlyInitializing() {
        require(_initializing, "Initializable: contract is not initializing");
        _;
    }

    /**
     * @dev Locks the contract, preventing any future reinitialization. This cannot be part of an initializer call.
     * Calling this in the constructor of a contract will prevent that contract from being initialized or reinitialized
     * to any version. It is recommended to use this to lock implementation contracts that are designed to be called
     * through proxies.
     *
     * Emits an {Initialized} event the first time it is successfully executed.
     */
    function _disableInitializers() internal virtual {
        require(!_initializing, "Initializable: contract is initializing");
        if (_initialized < type(uint8).max) {
            _initialized = type(uint8).max;
            emit Initialized(type(uint8).max);
        }
    }

    /**
     * @dev Internal function that returns the initialized version. Returns `_initialized`
     */
    function _getInitializedVersion() internal view returns (uint8) {
        return _initialized;
    }

    /**
     * @dev Internal function that returns the initialized version. Returns `_initializing`
     */
    function _isInitializing() internal view returns (bool) {
        return _initializing;
    }
}
abstract contract ReentrancyGuardUpgradeable is Initializable {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    function __ReentrancyGuard_init() internal onlyInitializing {
        __ReentrancyGuard_init_unchained();
    }

    function __ReentrancyGuard_init_unchained() internal onlyInitializing {
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        // On the first call to nonReentrant, _status will be _NOT_ENTERED
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _status = _ENTERED;
    }

    function _nonReentrantAfter() private {
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = _NOT_ENTERED;
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[49] private __gap;
}

pragma solidity ^0.8.12;

contract whitelistChecker is EIP712 {
    string private constant SIGNING_DOMAIN = "DevvE_LAUNCHPAD";
    string private constant SIGNATURE_VERSION = "1";

    struct Signer {
        address userAddress;
        address contractAddress;
        uint256 id;
        uint256 timestamp;
        bytes signature;
    }

    constructor() EIP712(SIGNING_DOMAIN, SIGNATURE_VERSION) {}

    function getSigner(Signer memory whitelist) public view returns (address) {
        return _verify(whitelist);
    }

    /// @notice Returns a hash of the given whitelist, prepared using EIP712 typed data hashing rules.

    function _hash(Signer memory whitelist) internal view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        keccak256(
                            "Signer(address userAddress,address contractAddress,uint256 id,uint256 timestamp)"
                        ),
                        whitelist.userAddress,
                        whitelist.contractAddress,
                        whitelist.id,
                        whitelist.timestamp
                    )
                )
            );
    }

    function _verify(Signer memory whitelist) internal view returns (address) {
        bytes32 digest = _hash(whitelist);
        return ECDSA.recover(digest, whitelist.signature);
    }
}

contract devveVesting is whitelistChecker ,ReentrancyGuardUpgradeable{
    IBEP20 public token;
    address public projectOwner;
    address public signer;
    address public adminWallet;
    bool private isStart;
    bool private iscollect;
    bool private ischeck;
    uint256 public activeLockDate;
    uint256 public totalDepositTokens;
    uint256 public totalAllocatedamount;
    uint256 public totalAirdropAllocationamount;
    uint256 public vestingEndTime;

    // mapping(uint256 => bool) private usedNonce;
    mapping(address=>mapping(uint=>bool)) public usedNonce;

    mapping (address => bool) public isUserAdded;

    mapping (address => bool) public isAirdropUserAdded;

    uint256 day;
    event TokenWithdraw(address indexed buyer, uint256 value,uint256 id);
    event RecoverToken(address indexed token, uint256 indexed amount);
    event RemoveUser(address _userAddress);
    event InvestorAddress(address account, uint256 _amout);

    modifier onlyAdmin() {
        require(msg.sender == adminWallet, "Caller is not Admin");
        _;
    }
    modifier setDate() {
        require(isStart == true, "wait for start date");
        _;
    }
    modifier _iscollect() {
        require(iscollect == true, "wait");
        _;
    }
    modifier check() {
        require(ischeck == true);
        _;
    }

    modifier onlyOwner() {
        require(msg.sender == projectOwner, "Not a ProjectOwner");
        _;
    }

    uint256 public TGEStartDate;
    uint256 public lockEndDate;
    uint256 public totalLinearUnits;
    uint256 public initialPercentage;
    uint256 public intermediaryPercentage;
    uint256 public intermediateTime;
    uint256 private middleTime;
    uint256 private linearTime;

    uint256 vestingPeriodDays = 12 * 30; // 10 months * 30 days

    receive() external payable {}

    constructor(
        uint256 _totalLinearUnits,
        uint256 timeBetweenUnits,
        uint256 linearStartDate,
        uint256 _startDate,
        address _tokenAddress,
        uint256 _initialPercentage,
        uint256 _intermediatePercentage,
        uint256 _intermediateTime,
        address _admin
    ) {
        require(_tokenAddress != address(0));
        middleTime = _intermediateTime;
        linearTime = linearStartDate;
        token = IBEP20(_tokenAddress);
        totalLinearUnits = _totalLinearUnits;
        adminWallet = _admin;
        day = timeBetweenUnits * 10 minutes;
        TGEStartDate = _startDate;
        initialPercentage = _initialPercentage;
        intermediaryPercentage = _intermediatePercentage;
        intermediateTime = _startDate + middleTime * 10 minutes;
        lockEndDate = intermediateTime + linearTime * 10 minutes;
        isStart = true;
        projectOwner = _admin;
        signer = _admin;
        vestingEndTime = lockEndDate + timeBetweenUnits * 10 minutes;
    }

    /* Withdraw the contract's balance to owner wallet*/
    function withdrawMatic() public onlyAdmin {
        payable(adminWallet).transfer(address(this).balance);
    }

    function getInvestorDetails(address _addr)
        public
        view
        returns (InvestorDetails memory)
    {
        return Investors[_addr];
    }

    function getContractTokenBalance() public view returns (uint256) {
        return token.balanceOf(address(this));
    }

    function setSigner(address _addr) public onlyAdmin {
        signer = _addr;
    }

    function remainningTokens() external view returns (uint256) {
        return totalDepositTokens - totalAllocatedamount;
    }

    struct Investor {
        address account;
        uint256 amount;
    }

    struct InvestorDetails {
        uint256 totalBalance;
        uint256 timeDifference;
        uint256 lastVestedTime;
        uint256 reminingUnitsToVest;
        uint256 tokensPerUnit;
        uint256 vestingBalance;
        uint256 airdropvestingBalance;
        uint256 airdropTokensPerDay;
        uint256 lastWithdrawalTimestamp;
        uint256 airdropVestingDays;
        uint256 initialAmount;
        uint256 nextAmount;
        uint256 airdroptotalBalance;
        bool isInitialAmountClaimed;
    }
    struct AirDropDetails {
        uint256 timeDifference;
        uint256 lastVestedTime;
        uint256 airdropvestingBalance;
        uint256 airdropTokensPerDay;
        uint256 lastWithdrawalTimestamp;
        uint256 airdropVestingDays;
        uint256 airdroptotalBalance;
        bool isInitialAmountClaimed;
    }
    mapping(address => InvestorDetails) public Investors;
    mapping(address => AirDropDetails) public AirDrops;



    function addInvestorDetails(uint amount, Signer memory _signer ) public nonReentrant{
        require(!usedNonce[msg.sender][_signer.timestamp],"Nonce : Invalid Nonce");
        require(getSigner(_signer) == signer, "!Signer");

        require (!isUserAdded[msg.sender],'User already whitelisted');

        usedNonce[msg.sender][_signer.timestamp]=true;
        isUserAdded[msg.sender] = true;

        InvestorDetails memory investor;
        // investor.totalBalance = (amount) * (10**18);
        investor.totalBalance = amount;
        investor.vestingBalance = investor.totalBalance;
        investor.reminingUnitsToVest = totalLinearUnits;
        investor.initialAmount =((investor.totalBalance) * (initialPercentage)) /100;
        investor.nextAmount =((investor.totalBalance) * (intermediaryPercentage)) /100;
        investor.tokensPerUnit = ((investor.totalBalance) - (investor.initialAmount) - (investor.nextAmount)) /totalLinearUnits;
        if(investor.initialAmount == 0 && investor.nextAmount == 0){
            investor.isInitialAmountClaimed = true;
        }
        Investors[_signer.userAddress] = investor; 
        totalAllocatedamount += investor.totalBalance;
    }

    function addInvestorsbyadmin(Investor[] memory vest) external onlyAdmin nonReentrant{
        for (uint i = 0;i < vest.length;i++) {

            require (!isUserAdded[vest[i].account],'User already whitelisted');
            isUserAdded[vest[i].account] = true;
            
            InvestorDetails memory investor;
            investor.totalBalance = vest[i].amount;
            investor.vestingBalance = investor.totalBalance;
            investor.reminingUnitsToVest = totalLinearUnits;
            investor.initialAmount =((investor.totalBalance) * (initialPercentage)) /100;
            investor.nextAmount =((investor.totalBalance) * (intermediaryPercentage)) /100;
            investor.tokensPerUnit = ((investor.totalBalance) - (investor.initialAmount) - (investor.nextAmount)) /totalLinearUnits;
            if(investor.initialAmount == 0 && investor.nextAmount == 0){
                investor.isInitialAmountClaimed = true;
            }
            Investors[vest[i].account] = investor; 
            totalAllocatedamount += investor.totalBalance;
            emit InvestorAddress(vest[i].account,vest[i].amount);
        }
    }

    function removeSingleUser(address _userAddress)public onlyOwner{
        require(isUserAdded[_userAddress],"Not a Investor");
        delete Investors[_userAddress];
        isUserAdded[_userAddress]=false;
        emit RemoveUser(_userAddress);
    }

    function addAirdrop(uint airdropamount, Signer memory _signer ) public nonReentrant {
      
        require(!usedNonce[msg.sender][_signer.timestamp],"Nonce : Invalid Nonce");
        require(getSigner(_signer) == signer, "!Signer");
        usedNonce[msg.sender][_signer.timestamp]=true;

        require (!isAirdropUserAdded[msg.sender],'User already whitelisted');
        isAirdropUserAdded[msg.sender] = true;
        
        AirDropDetails memory investor;
        investor.airdroptotalBalance = airdropamount;
        investor.airdropvestingBalance = investor.airdroptotalBalance;
        investor.airdropVestingDays = vestingPeriodDays;
        investor.airdropTokensPerDay = investor.airdroptotalBalance / vestingPeriodDays;
        investor.lastWithdrawalTimestamp = TGEStartDate;
        AirDrops[_signer.userAddress] = investor; 
        totalAirdropAllocationamount += investor.airdroptotalBalance;
    }

    function withdrawdevvefunction(Signer memory _signer) external nonReentrant {
        require(isStart = true, "wait for start date");
        require(block.timestamp >= TGEStartDate, "TGE has not started yet");
        require(!usedNonce[msg.sender][_signer.timestamp],"Nonce : Invalid Nonce");
        require(getSigner(_signer) == signer, "!Signer");
        usedNonce[msg.sender][_signer.timestamp]=true;
        uint256 id = 1;
        uint256 lineartoken = withdrawTokens();
        uint256 totaltokens = lineartoken;// airdroptoekns + lineartoken;
        require(totaltokens > 0, "wait for start date");
   
        
        token.transfer(msg.sender, totaltokens);
        emit TokenWithdraw(msg.sender, totaltokens,id);
    }

    function withdrawAirdropfunction(Signer memory _signer) external nonReentrant {
        require(isStart = true, "wait for start date");
        require(block.timestamp >= TGEStartDate, "TGE has not started yet");
        require(!usedNonce[msg.sender][_signer.timestamp],"Nonce : Invalid Nonce");
        require(getSigner(_signer) == signer, "!Signer");
           
        usedNonce[msg.sender][_signer.timestamp]=true;

        uint256 id = 2;
        uint256 airdroptoekns = withdrawAirdropTokens();

        uint256 totaltokens = airdroptoekns;// airdroptoekns + lineartoken;

        require(totaltokens > 0, "wait for start date");

        token.transfer(msg.sender, totaltokens);
        emit TokenWithdraw(msg.sender, totaltokens, id);
    }

    function withdrawTokens() internal setDate returns (uint256) {

        if (Investors[msg.sender].isInitialAmountClaimed) {
            if (block.timestamp >= lockEndDate) {
                activeLockDate = lockEndDate;

                /* Time difference to calculate the interval between now and last vested time. */
                uint256 timeDifference;
                if (Investors[msg.sender].lastVestedTime == 0) {

                    if (activeLockDate == 0) {
                        return 0; // Active lockdate was zero
                    }

                    timeDifference = block.timestamp - activeLockDate;
                } else {
                    timeDifference =
                        block.timestamp -
                        Investors[msg.sender].lastVestedTime;
                }

                uint256 numberOfUnitsCanBeVested = timeDifference / day;

                /* Remaining units to vest should be greater than 0 */
                if (Investors[msg.sender].reminingUnitsToVest == 0) {
                    return 0; // All units vested!
                }

                /* Number of units can be vested should be more than 0 */
                if (numberOfUnitsCanBeVested == 0) {
                    return 0; // Please wait till next vesting period!
                }

                if (
                    numberOfUnitsCanBeVested >=
                    Investors[msg.sender].reminingUnitsToVest
                ) {
                    numberOfUnitsCanBeVested = Investors[msg.sender]
                        .reminingUnitsToVest;
                }

                uint256 tokenToTransfer = numberOfUnitsCanBeVested *
                    Investors[msg.sender].tokensPerUnit;

                uint256 remainingUnits = Investors[msg.sender]
                    .reminingUnitsToVest;
                uint256 balance = Investors[msg.sender].vestingBalance;
                Investors[msg.sender]
                    .reminingUnitsToVest -= numberOfUnitsCanBeVested;
                Investors[msg.sender].vestingBalance -=
                    numberOfUnitsCanBeVested *
                    Investors[msg.sender].tokensPerUnit;
                Investors[msg.sender].lastVestedTime = block.timestamp;

                if (numberOfUnitsCanBeVested == remainingUnits) {
                    return balance;
                } else {
                    return tokenToTransfer;
                }
            } else {
                return 0; // Wait until lock period completes
            }
        } else {
            if (block.timestamp > intermediateTime) {
                if (iscollect == true) {
                    Investors[msg.sender].vestingBalance -= Investors[
                        msg.sender
                    ].nextAmount;
                    Investors[msg.sender].isInitialAmountClaimed = true;
                    uint256 amount = Investors[msg.sender].nextAmount;
                    return amount;
                } else {
                    Investors[msg.sender].vestingBalance -=
                        Investors[msg.sender].nextAmount +
                        Investors[msg.sender].initialAmount;
                    Investors[msg.sender].isInitialAmountClaimed = true;
                    uint256 amount = Investors[msg.sender].nextAmount +
                        Investors[msg.sender].initialAmount;
                    return amount;
                }
            } else {
                if (Investors[msg.sender].isInitialAmountClaimed) {
                    return 0; // Amount already withdrawn
                }
                if (block.timestamp <= TGEStartDate) {
                    return 0; // Wait Until the Start Date
                }
                if (Investors[msg.sender].initialAmount == 0) {
                    return 0; // Wait for next vest time
                }

                iscollect = true;
                uint256 amount = Investors[msg.sender].initialAmount;
                Investors[msg.sender].vestingBalance -= Investors[msg.sender]
                    .initialAmount;
                Investors[msg.sender].initialAmount = 0;
                return amount;
            }
        }
    }

 

    function withdrawAirdropTokens() private returns(uint256) {
        
        AirDropDetails storage investor = AirDrops[msg.sender];
        require(investor.airdropvestingBalance > 0, "No airdrop tokens to withdraw");
        require(block.timestamp >= TGEStartDate, "TGE has not started yet");

        uint256 elapsedTime = block.timestamp - investor.lastWithdrawalTimestamp;
        uint256 minutesElapsed = elapsedTime / 10 minutes; // Convert seconds to minutes
          uint256 tokensToWithdraw;
        if(minutesElapsed >= 1){
             tokensToWithdraw = minutesElapsed * investor.airdropTokensPerDay; // Adjust for minutes
            
            if (tokensToWithdraw > investor.airdropvestingBalance) {
                tokensToWithdraw = investor.airdropvestingBalance;
                investor.airdropvestingBalance = 0; // Set balance to 0
            } else {
                investor.airdropvestingBalance -= tokensToWithdraw;
            }
             investor.lastWithdrawalTimestamp = block.timestamp;
        }else{
             tokensToWithdraw = 0;
        }
        
        return tokensToWithdraw;
    }

    function getCurrentAirdropBalance(address investorAddress) public view returns (uint256){
        AirDropDetails storage investor = AirDrops[investorAddress];
        require(investor.airdropvestingBalance > 0,"No airdrop tokens available");
        require(block.timestamp >= TGEStartDate, "TGE has not started yet");
      

        uint256 elapsedTime = block.timestamp - investor.lastWithdrawalTimestamp;
        uint256 minutesElapsed = elapsedTime / 10 minutes; // Convert seconds to minutes
          uint256 tokensToWithdraw;
        if(minutesElapsed >= 1){
             tokensToWithdraw = minutesElapsed * investor.airdropTokensPerDay; // Adjust for minutes
        }else{
             tokensToWithdraw = 0;
        }
        
        if (tokensToWithdraw > investor.airdropvestingBalance) {
            tokensToWithdraw = investor.airdropvestingBalance;
        }

        return tokensToWithdraw;
    }

    function depositToken(uint256 amount) public {
        token.transferFrom(msg.sender, address(this), amount);
        totalDepositTokens += amount;
    }

    function recoverTokens(
        address _token,
        address _userAddress,
        uint256 amount
    ) public onlyAdmin {
        IBEP20(_token).transfer(_userAddress, amount);
        emit RecoverToken(_token, amount);
    }

    function transferOwnership(address _addr) external onlyAdmin {
        adminWallet = _addr;
    }

    function getAvailableBalance(address _addr)public view returns (uint256,uint256,uint256)
    {
        if (Investors[_addr].isInitialAmountClaimed) {

            if (block.timestamp >= lockEndDate) {
            uint256 lockDate = lockEndDate;
            uint256 hello = day;
            uint256 timeDifference;
            if (Investors[_addr].lastVestedTime == 0) {

              
                if(lockEndDate == 0) return (0, 0, 0);
                timeDifference = (block.timestamp) - (lockDate);

            } else {
                timeDifference =(block.timestamp) - (Investors[_addr].lastVestedTime);
            }


            if (Investors[_addr].reminingUnitsToVest == 0) {
                return (0, 0, 0); // All units vested!
            }


            uint256 numberOfUnitsCanBeVested;
            uint256 tokenToTransfer;
            numberOfUnitsCanBeVested = (timeDifference) / (hello);

          
            if (numberOfUnitsCanBeVested >= Investors[_addr].reminingUnitsToVest) {
                numberOfUnitsCanBeVested = Investors[_addr].reminingUnitsToVest;
            }
            tokenToTransfer = numberOfUnitsCanBeVested * Investors[_addr].tokensPerUnit;
            uint256 reminingUnits = Investors[_addr].reminingUnitsToVest;

            uint256 balance = Investors[_addr].vestingBalance;
            if (numberOfUnitsCanBeVested == reminingUnits)
                return (balance, 0, 0);
            else return (tokenToTransfer, reminingUnits, balance);

            }else{
                return (0, 0, 0);
            }

        } else {
            if (block.timestamp > intermediateTime) {
                if (iscollect) {
                    Investors[_addr].nextAmount == 0;
                    return (Investors[_addr].nextAmount, 0, 0);
                } else {
                    if (ischeck) return (0, 0, 0);
                    ischeck == true;
                    return (
                        (Investors[_addr].nextAmount +
                            Investors[_addr].initialAmount),
                        0,
                        0
                    );
                }
            } else {
                if (block.timestamp < TGEStartDate) {
                    return (0, 0, 0);
                } else {
                    iscollect == true;
                    Investors[_addr].initialAmount == 0;
                    return (Investors[_addr].initialAmount, 0, 0);
                }
            }
        }
    }

    function setStartDate(uint256 _startDate) external onlyAdmin {
        TGEStartDate = _startDate;
        intermediateTime = _startDate + middleTime * 10 minutes;
        lockEndDate = intermediateTime + linearTime * 10 minutes;
    }

    function setToken(address _token) external onlyAdmin {
        token = IBEP20(_token);
    }

}