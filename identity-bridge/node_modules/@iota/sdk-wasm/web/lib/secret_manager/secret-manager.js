// Copyright 2023 IOTA Stiftung
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
import { SecretManagerMethodHandler } from './secret-manager-method-handler';
import { TransactionPayload, } from '../types';
import { plainToInstance } from 'class-transformer';
/** The SecretManager to interact with nodes. */
var SecretManager = /** @class */ (function () {
    /**
     * @param options A secret manager type or a secret manager method handler.
     */
    function SecretManager(options) {
        this.methodHandler = new SecretManagerMethodHandler(options);
    }
    /**
     * Generate Ed25519 addresses.
     *
     * @param generateAddressesOptions Options to generate addresses.
     * @returns An array of generated addresses.
     */
    SecretManager.prototype.generateEd25519Addresses = function (generateAddressesOptions) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'generateEd25519Addresses',
                            data: {
                                options: generateAddressesOptions
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
     * Generate EVM addresses.
     *
     * @param generateAddressesOptions Options to generate addresses.
     * @returns An array of generated addresses.
     */
    SecretManager.prototype.generateEvmAddresses = function (generateAddressesOptions) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'generateEvmAddresses',
                            data: {
                                options: generateAddressesOptions
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
     * Store a mnemonic in the Stronghold vault.
     *
     * @param mnemonic The mnemonic to store.
     */
    SecretManager.prototype.storeMnemonic = function (mnemonic) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'storeMnemonic',
                            data: {
                                mnemonic: mnemonic
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
     * Sign a transaction.
     *
     * @param preparedTransactionData An instance of `PreparedTransactionData`.
     * @returns The corresponding transaction payload.
     */
    SecretManager.prototype.signTransaction = function (preparedTransactionData) {
        return __awaiter(this, void 0, void 0, function () {
            var response, parsed;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'signTransaction',
                            data: {
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
     * Create a signature unlock using the provided `secretManager`.
     *
     * @param transactionEssenceHash The hash of the transaction essence.
     * @param chain A BIP44 chain.
     * @returns The corresponding unlock.
     */
    SecretManager.prototype.signatureUnlock = function (transactionEssenceHash, chain) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'signatureUnlock',
                            data: {
                                transactionEssenceHash: transactionEssenceHash,
                                chain: chain
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
     * Signs a message with an Ed25519 private key.
     *
     * @param message The message to sign.
     * @param chain A BIP44 chain.
     * @returns The corresponding signature.
     */
    SecretManager.prototype.signEd25519 = function (message, chain) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'signEd25519',
                            data: {
                                message: message,
                                chain: chain
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
     * Signs a message with an Secp256k1Ecdsa private key.
     *
     * @param message The message to sign.
     * @param chain A BIP44 chain.
     * @returns The corresponding signature.
     */
    SecretManager.prototype.signSecp256k1Ecdsa = function (message, chain) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'signSecp256k1Ecdsa',
                            data: {
                                message: message,
                                chain: chain
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
     * Get the status of a Ledger Nano.
     */
    SecretManager.prototype.getLedgerNanoStatus = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getLedgerNanoStatus'
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    return SecretManager;
}());
export { SecretManager };
//# sourceMappingURL=secret-manager.js.map