// SPDX-License-Identifier: BUSL-1.1
pragma solidity >=0.5.0;

/// @dev is imported from
/// (https://github.com/LayerZero-Labs/LayerZero/blob/main/contracts/interfaces/ILayerZeroReceiver.sol)
interface ILayerZeroReceiver {
    // @notice LayerZero endpoint will invoke this function to deliver the message on the destination
    // @param _srcChainId - the source endpoint identifier
    // @param _srcAddress - the source sending contract address from the source chain
    // @param _nonce - the ordered message nonce
    // @param _payload - the signed payload is the UA bytes has encoded to be sent
    function lzReceive(uint16 _srcChainId, bytes calldata _srcAddress, uint64 _nonce, bytes calldata _payload)
        external;
}
