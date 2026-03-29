// Copyright 2021-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
import { ClientMethodHandler } from './client-method-handler';
import { PreparedTransactionData, } from '../types/client';
import { AliasOutput, BasicOutput, FoundryOutput, NftOutput, Block, UnlockCondition, TransactionPayload, MilestonePayload, Output, } from '../types/block';
import { UTXOInput, } from '../types';
import { OutputResponse, ReceiptsResponse, } from '../types/models/api';
import { plainToInstance } from 'class-transformer';
/** The Client to interact with nodes. */
var Client = /** @class */ (function () {
    /**
     * @param options client options or a client method handler.
     */
    function Client(options) {
        this.methodHandler = new ClientMethodHandler(options);
    }
    Client.prototype.destroy = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.methodHandler.destroy()];
            });
        });
    };
    /**
     * Get the node information together with the url of the used node.
     */
    Client.prototype.getInfo = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getInfo'
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get network related information such as protocol parameters and minimum pow score.
     */
    Client.prototype.getNetworkInfo = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getNetworkInfo'
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Fetch alias/basic/NFT/foundry output IDs based on the given query parameters.
     */
    Client.prototype.outputIds = function (queryParameters) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'outputIds',
                            data: {
                                queryParameters: queryParameters
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Fetch basic output IDs based on the given query parameters.
     */
    Client.prototype.basicOutputIds = function (queryParameters) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'basicOutputIds',
                            data: {
                                queryParameters: queryParameters
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get output from a given output ID.
     */
    Client.prototype.getOutput = function (outputId) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getOutput',
                            data: {
                                outputId: outputId
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        return [2 /*return*/, plainToInstance(OutputResponse, parsed.payload)];
                }
            });
        });
    };
    /**
     * Fetch OutputResponse from given output IDs. Requests are sent in parallel.
     */
    Client.prototype.getOutputs = function (outputIds) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getOutputs',
                            data: {
                                outputIds: outputIds
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        return [2 /*return*/, plainToInstance(OutputResponse, parsed.payload)];
                }
            });
        });
    };
    /**
     * Build and post a block.
     *
     * @param secretManager One of the supported secret managers.
     * @param options Options on how to build a block.
     * @returns The block ID and the posted block itself.
     */
    Client.prototype.buildAndPostBlock = function (secretManager, options) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed, block;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (options &&
                            options.output &&
                            typeof options.output.amount === 'bigint') {
                            options.output.amount = options.output.amount.toString(10);
                        }
                        if (options &&
                            options.outputHex &&
                            typeof options.outputHex.amount === 'bigint') {
                            options.outputHex.amount = options.outputHex.amount.toString(10);
                        }
                        return [4 /*yield*/, this.methodHandler.callMethod({
                                name: 'buildAndPostBlock',
                                data: {
                                    secretManager: secretManager,
                                    options: options
                                }
                            })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        block = plainToInstance(Block, parsed.payload[1]);
                        return [2 /*return*/, [parsed.payload[0], block]];
                }
            });
        });
    };
    /**
     * Request tips from the node.
     * The tips can be considered as non-lazy and are therefore ideal for attaching a block to the Tangle.
     * @returns An array of tips represented by their block IDs.
     */
    Client.prototype.getTips = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getTips'
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Post a block in JSON format.
     *
     * @param block The block to post.
     * @returns The block ID once the block has been posted.
     */
    Client.prototype.postBlock = function (block) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'postBlock',
                            data: {
                                block: block
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get a block in JSON format.
     *
     * @param blockId The corresponding block ID of the requested block.
     * @returns The requested block.
     */
    Client.prototype.getBlock = function (blockId) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getBlock',
                            data: {
                                blockId: blockId
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        return [2 /*return*/, plainToInstance(Block, parsed.payload)];
                }
            });
        });
    };
    /**
     * Get the metadata of a block.
     *
     * @param blockId The corresponding block ID of the requested block metadata.
     * @returns The requested block metadata.
     */
    Client.prototype.getBlockMetadata = function (blockId) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getBlockMetadata',
                            data: {
                                blockId: blockId
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Find inputs from addresses for a given amount (useful for offline signing).
     *
     * @param addresses A list of included addresses.
     * @param amount The amount to find inputs for.
     * @returns An array of UTXO inputs.
     */
    Client.prototype.findInputs = function (addresses, amount) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'findInputs',
                            data: {
                                addresses: addresses,
                                amount: Number(amount)
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        return [2 /*return*/, plainToInstance(UTXOInput, parsed.payload)];
                }
            });
        });
    };
    /**
     * Prepare a transaction for signing.
     *
     * @param secretManager One of the supported secret managers.
     * @param options Options to build a block.
     * @returns An instance of `PreparedTransactionData`.
     */
    Client.prototype.prepareTransaction = function (secretManager, options) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'prepareTransaction',
                            data: {
                                secretManager: secretManager,
                                options: options
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        return [2 /*return*/, plainToInstance(PreparedTransactionData, parsed.payload)];
                }
            });
        });
    };
    /**
     * Sign a transaction.
     *
     * @param secretManager One of the supported secret managers.
     * @param preparedTransactionData An instance of `PreparedTransactionData`.
     * @returns The corresponding transaction payload.
     */
    Client.prototype.signTransaction = function (secretManager, preparedTransactionData) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'signTransaction',
                            data: {
                                secretManager: secretManager,
                                preparedTransactionData: preparedTransactionData
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        return [2 /*return*/, plainToInstance(TransactionPayload, parsed.payload)];
                }
            });
        });
    };
    /**
     * Create a signature unlock using the given secret manager.
     *
     * @param secretManager One of the supported secret managers.
     * @param transactionEssenceHash The hash of the transaction essence.
     * @param chain A BIP44 chain
     * @returns The corresponding unlock condition.
     */
    Client.prototype.signatureUnlock = function (secretManager, transactionEssenceHash, chain) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'signatureUnlock',
                            data: {
                                secretManager: secretManager,
                                transactionEssenceHash: transactionEssenceHash,
                                chain: chain
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, UnlockCondition.parse(JSON.parse(response).payload)];
                }
            });
        });
    };
    /**
     * Submit a payload in a block.
     *
     * @param payload The payload to post.
     * @returns The block ID followed by the block containing the payload.
     */
    Client.prototype.postBlockPayload = function (payload) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed, block;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'postBlockPayload',
                            data: {
                                payload: payload
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        block = plainToInstance(Block, parsed.payload[1]);
                        return [2 /*return*/, [parsed.payload[0], block]];
                }
            });
        });
    };
    /**
     * Get a node candidate from the healthy node pool.
     */
    Client.prototype.getNode = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getNode'
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get the ID of the network the node is connected to.
     */
    Client.prototype.getNetworkId = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getNetworkId'
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get the Bech32 HRP (human readable part) of the network the node is connected to.
     */
    Client.prototype.getBech32Hrp = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getBech32Hrp'
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get the minimum PoW score.
     */
    Client.prototype.getMinPowScore = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getMinPowScore'
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get the tips interval.
     */
    Client.prototype.getTipsInterval = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getTipsInterval'
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get the token supply.
     */
    Client.prototype.getTokenSupply = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.getProtocolParameters()];
                    case 1: return [2 /*return*/, (_a.sent()).tokenSupply];
                }
            });
        });
    };
    /**
     * Get the protocol parameters.
     */
    Client.prototype.getProtocolParameters = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getProtocolParameters'
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Check whether local pow should be used or not.
     */
    Client.prototype.getLocalPow = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getLocalPow'
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Check whether to fallback to local proof of work in case the node doesn't support remote PoW.
     */
    Client.prototype.getFallbackToLocalPow = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getFallbackToLocalPow'
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get the health of a node.
     *
     * @param url The URL of the node.
     */
    Client.prototype.getHealth = function (url) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getHealth',
                            data: {
                                url: url
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get the info about the node.
     *
     * @param url The URL of the node.
     * @param auth An authentication object (e.g. JWT).
     */
    Client.prototype.getNodeInfo = function (url, auth) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getNodeInfo',
                            data: {
                                url: url,
                                auth: auth
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get the peers of the node.
     */
    Client.prototype.getPeers = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getPeers'
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Post block as raw bytes, returns the block ID.
     *
     * @param block The block.
     * @returns The ID of the posted block.
     */
    Client.prototype.postBlockRaw = function (block) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'postBlockRaw',
                            data: {
                                block: block
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get block as raw bytes.
     *
     * @param blockId The block ID of the requested block.
     * @returns The raw bytes of the requested block.
     */
    Client.prototype.getBlockRaw = function (blockId) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getBlockRaw',
                            data: {
                                blockId: blockId
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get a milestone payload by its ID.
     *
     * @param milestoneId The ID of the requested milestone.
     * @returns The corresponding milestone payload.
     */
    Client.prototype.getMilestoneById = function (milestoneId) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getMilestoneById',
                            data: {
                                milestoneId: milestoneId
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        return [2 /*return*/, plainToInstance(MilestonePayload, parsed.payload)];
                }
            });
        });
    };
    /**
     * Get all UTXO changes of a milestone by its ID.
     *
     * @param milestoneId The ID of the milestone that applied the UTXO changes.
     * @returns A milestone UTXO changes response.
     */
    Client.prototype.getUtxoChangesById = function (milestoneId) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getUtxoChangesById',
                            data: {
                                milestoneId: milestoneId
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get a milestone payload by its index.
     *
     * @param index The index of the requested milestone.
     * @returns The corresponding milestone payload.
     */
    Client.prototype.getMilestoneByIndex = function (index) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getMilestoneByIndex',
                            data: {
                                index: index
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        return [2 /*return*/, plainToInstance(MilestonePayload, parsed.payload)];
                }
            });
        });
    };
    /**
     * Get all UTXO changes of a milestone by its index.
     *
     * @param index The index of the milestone that applied the UTXO changes.
     * @returns A milestone UTXO changes response.
     */
    Client.prototype.getUtxoChangesByIndex = function (index) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getUtxoChangesByIndex',
                            data: {
                                index: index
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get all receipts.
     */
    Client.prototype.getReceipts = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getReceipts'
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        return [2 /*return*/, plainToInstance(ReceiptsResponse, parsed.payload)];
                }
            });
        });
    };
    /**
     * Get the receipts at a given milestone index.
     *
     * @param milestoneIndex The index of the milestone that migrated funds to the new network.
     */
    Client.prototype.getReceiptsMigratedAt = function (milestoneIndex) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getReceiptsMigratedAt',
                            data: {
                                milestoneIndex: milestoneIndex
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        return [2 /*return*/, plainToInstance(ReceiptsResponse, parsed.payload)];
                }
            });
        });
    };
    /**
     * Get the treasury output.
     */
    Client.prototype.getTreasury = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getTreasury'
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, Output.parse(JSON.parse(response).payload)];
                }
            });
        });
    };
    /**
     * Get the included block of a given transaction.
     *
     * @param transactionId The ID of the transaction.
     * @returns The included block that contained the transaction.
     */
    Client.prototype.getIncludedBlock = function (transactionId) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getIncludedBlock',
                            data: {
                                transactionId: transactionId
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        return [2 /*return*/, plainToInstance(Block, parsed.payload)];
                }
            });
        });
    };
    /**
     * Get the metadata of the included block of a given transaction.
     *
     * @param transactionId The ID of the transaction.
     * @returns The included block that contained the transaction.
     */
    Client.prototype.getIncludedBlockMetadata = function (transactionId) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getIncludedBlockMetadata',
                            data: {
                                transactionId: transactionId
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        return [2 /*return*/, plainToInstance(Block, parsed.payload)];
                }
            });
        });
    };
    /**
     * Convert a hex encoded address to a Bech32 encoded address.
     *
     * @param hex The hexadecimal string representation of an address.
     * @param bech32Hrp The Bech32 HRP (human readable part) to be used.
     * @returns The corresponding Bech32 address.
     */
    Client.prototype.hexToBech32 = function (hex, bech32Hrp) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'hexToBech32',
                            data: {
                                hex: hex,
                                bech32Hrp: bech32Hrp
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Convert an Alias ID to a Bech32 encoded address.
     *
     * @param aliasId An Alias ID.
     * @param bech32Hrp The Bech32 HRP (human readable part) to be used.
     * @returns The corresponding Bech32 address.
     */
    Client.prototype.aliasIdToBech32 = function (aliasId, bech32Hrp) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'aliasIdToBech32',
                            data: {
                                aliasId: aliasId,
                                bech32Hrp: bech32Hrp
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Convert an NFT ID to a Bech32 encoded address.
     *
     * @param nftId An NFT ID.
     * @param bech32Hrp The Bech32 HRP (human readable part) to be used.
     * @returns The corresponding Bech32 address.
     */
    Client.prototype.nftIdToBech32 = function (nftId, bech32Hrp) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'nftIdToBech32',
                            data: {
                                nftId: nftId,
                                bech32Hrp: bech32Hrp
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Convert a hex encoded public key to a Bech32 encoded address.
     *
     * @param hex The hexadecimal string representation of a public key.
     * @param bech32Hrp The Bech32 HRP (human readable part) to be used.
     * @returns The corresponding Bech32 address.
     */
    Client.prototype.hexPublicKeyToBech32Address = function (hex, bech32Hrp) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'hexPublicKeyToBech32Address',
                            data: {
                                hex: hex,
                                bech32Hrp: bech32Hrp
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get the corresponding output IDs given a list of Alias query parameters.
     *
     * @param queryParameters An array of `AliasQueryParameter`s.
     * @returns A paginated query response of corresponding output IDs.
     */
    Client.prototype.aliasOutputIds = function (queryParameters) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'aliasOutputIds',
                            data: {
                                queryParameters: queryParameters
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get the corresponding output ID from an Alias ID.
     *
     * @param aliasId An Alias ID.
     * @returns The corresponding output ID.
     */
    Client.prototype.aliasOutputId = function (aliasId) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'aliasOutputId',
                            data: {
                                aliasId: aliasId
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get the corresponding output IDs given a list of NFT query parameters.
     *
     * @param queryParameters An array of `NftQueryParameter`s.
     * @returns A paginated query response of corresponding output IDs.
     */
    Client.prototype.nftOutputIds = function (queryParameters) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'nftOutputIds',
                            data: {
                                queryParameters: queryParameters
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get the corresponding output ID from an NFT ID.
     *
     * @param nftId An NFT ID.
     * @returns The corresponding output ID.
     */
    Client.prototype.nftOutputId = function (nftId) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'nftOutputId',
                            data: {
                                nftId: nftId
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get the corresponding output IDs given a list of Foundry query parameters.
     *
     * @param queryParameters An array of `FoundryQueryParameter`s.
     * @returns A paginated query response of corresponding output IDs.
     */
    Client.prototype.foundryOutputIds = function (queryParameters) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'foundryOutputIds',
                            data: {
                                queryParameters: queryParameters
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get the corresponding output ID from a Foundry ID.
     *
     * @param foundryId A Foundry ID.
     * @returns The corresponding output ID.
     */
    Client.prototype.foundryOutputId = function (foundryId) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'foundryOutputId',
                            data: {
                                foundryId: foundryId
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get outputs from provided output IDs (requests are sent
     * in parallel and errors are ignored, can be useful for spent outputs)
     *
     * @param outputIds An array of output IDs.
     * @returns An array of corresponding output responses.
     */
    Client.prototype.getOutputsIgnoreErrors = function (outputIds) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getOutputsIgnoreErrors',
                            data: {
                                outputIds: outputIds
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        return [2 /*return*/, plainToInstance(OutputResponse, parsed.payload)];
                }
            });
        });
    };
    /**
     * Find blocks by their IDs.
     *
     * @param blockIds An array of `BlockId`s.
     * @returns An array of corresponding blocks.
     */
    Client.prototype.findBlocks = function (blockIds) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'findBlocks',
                            data: {
                                blockIds: blockIds
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        return [2 /*return*/, plainToInstance(Block, parsed.payload)];
                }
            });
        });
    };
    /**
     * Retry (promote or reattach) a block given its block ID.
     *
     * **Note**: Blocks should be retried only if they are valid and haven't been confirmed for some time.
     *
     * @param blockId The ID of the block to retry.
     * @returns The included block.
     */
    Client.prototype.retry = function (blockId) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed, block;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'retry',
                            data: {
                                blockId: blockId
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        block = plainToInstance(Block, parsed.payload[1]);
                        return [2 /*return*/, [parsed.payload[0], block]];
                }
            });
        });
    };
    /**
     * Retry (promote or reattach) a block given its block ID until it's included
     * (i.e. referenced by a milestone).
     *
     * @param blockId The ID of the block to retry.
     * @param interval A retry interval in seconds. Defaults to 5.
     * @param maxAttempts A maximum number of retries. Defaults to 40.
     * @returns The included block at first position and additional reattached blocks.
     */
    Client.prototype.retryUntilIncluded = function (blockId, interval, maxAttempts) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed, arr;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'retryUntilIncluded',
                            data: {
                                blockId: blockId,
                                interval: interval,
                                maxAttempts: maxAttempts
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        arr = [];
                        parsed.payload.forEach(function (payload) {
                            arr.push([payload[0], plainToInstance(Block, payload[1])]);
                        });
                        return [2 /*return*/, arr];
                }
            });
        });
    };
    /**
     * Consolidate all funds from a range of addresses to the address with the lowest index in that range.
     *
     * @param secretManager One of supported secret managers.
     * @param generateAddressesOptions Options for generating addresses.
     * @returns The address to which the funds got consolidated, if any were available.
     */
    Client.prototype.consolidateFunds = function (secretManager, generateAddressesOptions) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'consolidateFunds',
                            data: {
                                secretManager: secretManager,
                                generateAddressesOptions: generateAddressesOptions
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Reattach a block.
     *
     * **Note**: Blocks can be reattached only if they are valid and haven't been confirmed for some time.
     *
     * @param blockId The ID of the block to reattach.
     * @returns The included block.
     */
    Client.prototype.reattach = function (blockId) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed, block;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'reattach',
                            data: {
                                blockId: blockId
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        block = plainToInstance(Block, parsed.payload[1]);
                        return [2 /*return*/, [parsed.payload[0], block]];
                }
            });
        });
    };
    /**
     * Reattach a block without checking whether it should be reattached.
     *
     * @param blockId The ID of the block to reattach.
     * @returns The included block.
     */
    Client.prototype.reattachUnchecked = function (blockId) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed, block;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'reattachUnchecked',
                            data: {
                                blockId: blockId
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        block = plainToInstance(Block, parsed.payload[1]);
                        return [2 /*return*/, [parsed.payload[0], block]];
                }
            });
        });
    };
    /**
     * Promote a block.
     *
     * **NOTE**: The method validates whether a promotion is necessary through `get_block`. If not, the
     * method will error out and will not do unnecessary promotions.
     *
     * @param blockId The ID of the block to promote.
     * @returns The included block.
     */
    Client.prototype.promote = function (blockId) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed, block;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'promote',
                            data: {
                                blockId: blockId
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        block = plainToInstance(Block, parsed.payload[1]);
                        return [2 /*return*/, [parsed.payload[0], block]];
                }
            });
        });
    };
    /**
     * Promote a block without checking if it should be promoted.
     *
     * @param blockId The ID of the block to promote.
     * @returns The included block.
     */
    Client.prototype.promoteUnchecked = function (blockId) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed, block;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'promoteUnchecked',
                            data: {
                                blockId: blockId
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        block = plainToInstance(Block, parsed.payload[1]);
                        return [2 /*return*/, [parsed.payload[0], block]];
                }
            });
        });
    };
    /**
     * Return the unhealthy nodes.
     */
    Client.prototype.unhealthyNodes = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'unhealthyNodes'
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Build a basic output.
     *
     * @param params An instance of `BasicOutputBuilderParams`.
     */
    Client.prototype.buildBasicOutput = function (params) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (params.amount && typeof params.amount === 'bigint') {
                            params.amount = params.amount.toString(10);
                        }
                        return [4 /*yield*/, this.methodHandler.callMethod({
                                name: 'buildBasicOutput',
                                data: params
                            })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        return [2 /*return*/, plainToInstance(BasicOutput, parsed.payload)];
                }
            });
        });
    };
    /**
     * Build an alias output.
     *
     * @param params An instance of `AliasOutputBuilderParams`.
     */
    Client.prototype.buildAliasOutput = function (params) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (params.amount && typeof params.amount === 'bigint') {
                            params.amount = params.amount.toString(10);
                        }
                        return [4 /*yield*/, this.methodHandler.callMethod({
                                name: 'buildAliasOutput',
                                data: params
                            })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        return [2 /*return*/, plainToInstance(AliasOutput, parsed.payload)];
                }
            });
        });
    };
    /**
     * Build a foundry output.
     *
     * @param params An instance of `FoundryOutputBuilderParams`.
     */
    Client.prototype.buildFoundryOutput = function (params) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (params.amount && typeof params.amount === 'bigint') {
                            params.amount = params.amount.toString(10);
                        }
                        return [4 /*yield*/, this.methodHandler.callMethod({
                                name: 'buildFoundryOutput',
                                data: params
                            })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        return [2 /*return*/, plainToInstance(FoundryOutput, parsed.payload)];
                }
            });
        });
    };
    /**
     * Build an NFT output.
     *
     * @param params An instance of `NftOutputBuilderParams`.
     */
    Client.prototype.buildNftOutput = function (params) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (params.amount && typeof params.amount === 'bigint') {
                            params.amount = params.amount.toString(10);
                        }
                        return [4 /*yield*/, this.methodHandler.callMethod({
                                name: 'buildNftOutput',
                                data: params
                            })];
                    case 1:
                        response = _a.sent();
                        parsed = JSON.parse(response);
                        return [2 /*return*/, plainToInstance(NftOutput, parsed.payload)];
                }
            });
        });
    };
    /**
     * Listen to MQTT events.
     *
     * @param topics An array of MQTT topics to listen to.
     */
    Client.prototype.listenMqtt = function (topics, callback) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.methodHandler.listen(topics, callback)];
            });
        });
    };
    /**
     * Stop listening to certain MQTT events.
     *
     * @param topics An array of MQTT topics to stop listening to.
     */
    Client.prototype.clearMqttListeners = function (topics) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'clearListeners',
                            data: {
                                topics: topics
                            }
                        })];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * Calculate the minimum required storage deposit for an output.
     *
     * @param output The output to calculate the minimum deposit amount for.
     * @returns The minimum required amount.
     */
    Client.prototype.minimumRequiredStorageDeposit = function (output) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'minimumRequiredStorageDeposit',
                            data: {
                                output: output
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Request funds from a faucet.
     *
     * Example URLs: `https://faucet.testnet.shimmer.network/api/enqueue` or `http://localhost:8091/api/enqueue`.
     *
     * @param url The URL of the faucet.
     * @param address The address to send the funds to.
     * @returns The faucet response.
     */
    Client.prototype.requestFundsFromFaucet = function (url, address) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'requestFundsFromFaucet',
                            data: { url: url, address: address }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Extension method which provides request methods for plugins.
     *
     * @param basePluginPath The base path for the plugin eg indexer/v1/ .
     * @param method The http method.
     * @param endpoint The path for the plugin request.
     * @param queryParams Additional query params for the request.
     * @param request The request object.
     * @returns The response json.
     */
    Client.prototype.callPluginRoute = function (basePluginPath, method, endpoint, queryParams, request) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'callPluginRoute',
                            data: {
                                basePluginPath: basePluginPath,
                                method: method,
                                endpoint: endpoint,
                                queryParams: queryParams !== null && queryParams !== void 0 ? queryParams : [],
                                request: request
                            }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    return Client;
}());
export { Client };
//# sourceMappingURL=client.js.map