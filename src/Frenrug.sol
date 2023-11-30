// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {Banked} from "./pattern/Banked.sol";
import {Ownable} from "solady/auth/Ownable.sol";
import {Delegated} from "./pattern/Delegated.sol";
import {Configured} from "./pattern/Configured.sol";
import {SD59x18, div, sd} from "@prb/math/SD59x18.sol";
import {Permissioned} from "./pattern/Permissioned.sol";
import {FriendtechManager} from "./FriendtechManager.sol";
import {CallbackConsumer} from "infernet/consumer/Callback.sol";
import {IDataAttestation} from "./interfaces/IDataAttestation.sol";

/// @title Frenrug
/// @notice https://frenrug.com
/// @notice Uses Infernet SDK: https://ritual.net
/// @notice Frenrug is an on-chain AI agent that lives in a friend.tech chatroom managing a portfolio of friend.tech keys
/// @dev Inherited contracts also inherit Ownable; ensure base Ownable is first in inheritance hiearchy
/// @dev Allows off-chain created Infernet subscriptions to initialize flow
/// @dev After set number of received LLM responses, initializes a summarization callback
/// @dev Enables summarization callback to execute trade and emit result
/// @dev Notice that while gas optimizations (particularly in calldata reduction for L2 costs by packing vector inputs) are possible they have been forgone in favor of simplicity and readability
contract Frenrug is Ownable, FriendtechManager, Banked, Configured, Permissioned, Delegated, CallbackConsumer {
    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice A message is a proposal to take some action for a (key, id) pair
    struct Message {
        /// @notice Chatroom message identifier
        uint48 id;
        /// @notice Proposed key to take action on
        address key;
        /// @notice LLM hashed inputs
        bytes32[] inputs;
        /// @notice LLM rationales for action
        string[] rationales;
        /// @notice Responding nodes (mapped 1:1 to rationales)
        address[] nodes;
        /// @notice LLM output embedding vectors
        int256[] vectors;
    }

    /*//////////////////////////////////////////////////////////////
                                 ENUMS
    //////////////////////////////////////////////////////////////*/

    /// @notice Possible actions to take for a message
    enum MessageAction {
        Noop,
        Buy,
        Sell
    }

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Upper bound on gas price for acceptable Infernet callback response
    /// @dev Set to MAX_UINT48 to keep unbounded
    uint48 private constant MAX_CALLBACK_GAS_PRICE = type(uint48).max;

    /*//////////////////////////////////////////////////////////////
                                MUTABLE
    //////////////////////////////////////////////////////////////*/

    /// @notice subscriptionId => associated message
    mapping(uint32 => Message) public messages;

    /// @notice Summarizer callback subscriptionId => associated message subscriptionId
    mapping(uint32 => uint32) public summarizerToMessage;

    /// @notice index => attested inputs
    /// @dev Always modified prior to calling `verifyWithDataAttestation`
    /// @dev Index 0: poseidon hash
    /// @dev Index 1: message action
    mapping(uint256 => uint256) public attestedInputs;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Emitted when an action is executed and a message response generated
    /// @param id room message ID
    /// @param key executed friend.tech key
    /// @param action proposed by summarizer
    /// @param failure execution failure status
    /// @param rationales LLM rationales
    /// @param nodes responding LLM nodes
    /// @param rawInput raw input embedding vector
    /// @param hashedInput poseidon hash input
    /// @dev Note that it is not necessary to emit much of this data (since present in `messages`), but we emit for indexer convenience
    event MessageResponse(
        uint48 indexed id,
        address indexed key,
        MessageAction action,
        ExecutionFailure failure,
        string[] rationales,
        address[] nodes,
        bytes rawInput,
        uint256 hashedInput
    );

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Thrown if DA or proof is invalid when verified
    /// @dev 4-byte signature: `0x25e255b8`
    error InvalidVerification();

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /// Create new Frenrug
    /// @param _config global configuration
    /// @param _friendtech FriendtechSharesV1 address
    /// @param _coordinator Infernet coordinator
    /// @param _nodes initial permissioned Infernet nodes
    /// @param _status initial permissioned Infernet node statuses
    constructor(
        Config memory _config,
        address _friendtech,
        address _coordinator,
        address[] memory _nodes,
        bool[] memory _status
    ) FriendtechManager(_friendtech) CallbackConsumer(_coordinator) {
        // Intialize contract ownership to caller
        _initializeOwner(msg.sender);
        // Initialize global configuration
        _updateConfig(_config);
        // Initialize node allowlist
        _updateAllowlist(_nodes, _status);
    }

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice Requests summarizer compute container to process LLM responses
    /// @dev Called after sufficient LLM container responses have been received
    /// @param subscriptionId ID of message subscription to summarize
    function _initiateSummarizerRequest(uint32 subscriptionId) internal {
        // Initialize callback request for summarization
        uint32 id = _requestCompute(
            config.containerId,
            "", // Inputs empty since we opt to use `getContainerInputs()`
            MAX_CALLBACK_GAS_PRICE,
            config.maxCallbackGasLimit,
            1 // `redundancy == 1` since executing a model with a succinct proof
        );

        // Store summarizer ID to message ID
        summarizerToMessage[id] = subscriptionId;
    }

    /// @notice Processes an off-chain created LLM response subscription
    /// @param subscriptionId subscription ID
    /// @param redundancy request redundancy count
    /// @param node delivering node (permissioned)
    /// @param input compute container input (in this case: {hashed input, id, key})
    /// @param output compute container output (in this case: {LLM rationale string, LLM embedding vectors})
    /// @param proof empty (no succinct proof for LLM response)
    function _processLLMResponse(
        uint32 subscriptionId,
        uint16 redundancy,
        address node,
        bytes calldata input,
        bytes calldata output,
        bytes calldata proof
    ) internal {
        // Collect message (or initialize)
        Message storage message = messages[subscriptionId];

        // Decode output (LLM rationale string, LLM embedding vectors)
        (string memory rationale, bytes memory vectorString) = abi.decode(output, (string, bytes));
        (int256[] memory vectors) = abi.decode(vectorString, (int256[]));

        // Store node, rationale
        message.nodes.push(node);
        message.rationales.push(rationale);

        // If first response for subscription
        if (redundancy == 1) {
            // Decode {hashed input, id, key} from input
            (bytes32 hashed, uint48 id, address key) = abi.decode(input, (bytes32, uint48, address));

            // Update message
            message.id = id;
            message.key = key;
            message.inputs.push(hashed);

            // Initialize vectors array
            for (uint256 i = 0; i < vectors.length; i++) {
                message.vectors.push(vectors[i]);
            }
        } else {
            // In-place update vectors array (online addition)
            for (uint256 i = 0; i < vectors.length; i++) {
                message.vectors[i] += vectors[i];
            }
        }

        // If this is the last response for a subscriptionId, kick off summarizer request
        if (redundancy == config.nodes) {
            _initiateSummarizerRequest(subscriptionId);
        }
    }

    /// @notice Process a summarized decision, execution an action, emitting a response + rationale
    /// @param subscriptionId summarizer callback subscription ID
    /// @param input compute container input (in this case, {raw input vector, poseidon hash})
    /// @param output compute container output (in this case, {action})
    /// @param proof compute container proof (in this case, {EZKL proof})
    function _processSummarizerResponse(
        uint32 subscriptionId,
        bytes calldata input,
        bytes calldata output,
        bytes calldata proof
    ) internal {
        // Collect associated message subscription ID
        uint32 id = summarizerToMessage[subscriptionId];

        // Decode input, output
        (bytes memory rawInputVector, uint256 poseidonHash) = abi.decode(input, (bytes, uint256));
        (MessageAction action) = abi.decode(output, (MessageAction));

        // Update Data Attestation inputs (poseiden hash, action)
        attestedInputs[0] = poseidonHash;
        attestedInputs[1] = uint256(action);

        // Verify EKZL proof
        bool verified = IDataAttestation(config.attestor).verifyWithDataAttestation(config.verifier, proof);
        if (!verified) {
            revert InvalidVerification();
        }

        // Collect message
        Message memory message = messages[id];

        // Execute based on action
        ExecutionFailure failure = ExecutionFailure.None;
        if (action == MessageAction.Buy) {
            failure = buyKey(message.key);
        } else if (action == MessageAction.Sell) {
            failure = sellKey(message.key);
        }

        // Emit execution event
        emit MessageResponse(
            message.id, message.key, action, failure, message.rationales, message.nodes, rawInputVector, poseidonHash
        );
    }

    /// @notice Incoming callback receive function
    /// @dev Overriding `CallbackConsumer._receiveCompute`
    /// @dev Restricted to allowlist of permissioned nodes
    function _receiveCompute(
        uint32 subscriptionId,
        uint32 interval,
        uint16 redundancy,
        address node,
        bytes calldata input,
        bytes calldata output,
        bytes calldata proof
    ) internal override onlyPermissionedNode(node) {
        // Check if receiving compute output for a known summarization request
        if (summarizerToMessage[subscriptionId] != 0) {
            // Process summarizer response
            return _processSummarizerResponse(subscriptionId, input, output, proof);
        }

        // Else, we are receiving container response for some off-chain LLM subscription
        // At this point, we could perform a check to ensure that redundancy > configured redundancy, but not necessary since permissioned node set
        // At this point, we could enforce `interval == 1`, but not required since we can assume off-chain subscription creator is enforcing in subscription config
        // Thus, we process some LLM response
        return _processLLMResponse(subscriptionId, redundancy, node, input, output, proof);
    }

    /*//////////////////////////////////////////////////////////////
                               FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /// @notice View function to broadcast dynamic container inputs to off-chain Infernet nodes
    /// @notice Broadcasts averaged output embedding vectors
    /// @param subscriptionId subscription ID to collect container inputs for
    /// @param interval subscription interval to collect container inputs for
    /// @param timestamp timestamp at which container inputs are collected
    /// @param caller calling address
    function getContainerInputs(uint32 subscriptionId, uint32 interval, uint32 timestamp, address caller)
        external
        view
        virtual
        returns (bytes memory)
    {
        // Collect message subscription ID based on summarizer subscription ID
        uint32 messageId = summarizerToMessage[subscriptionId];

        // Setup reference to LLM output embedding vectors
        int256[] memory vectors = messages[messageId].vectors;

        // Create new averaged vector array
        int256[] memory averaged = new int256[](vectors.length);

        // Average all vectors
        SD59x18 divisor = sd(int256(uint256(config.nodes)) * 1e18);
        for (uint256 i = 0; i < vectors.length; i++) {
            averaged[i] = div(sd(vectors[i]), divisor).unwrap();
        }

        // Encode averaged vectors
        bytes memory inputs = abi.encode(averaged);
        return inputs;
    }
}
