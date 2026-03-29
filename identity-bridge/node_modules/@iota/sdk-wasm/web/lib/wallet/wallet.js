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
import { WalletMethodHandler } from './wallet-method-handler';
import { Account } from './account';
/** The Wallet class. */
var Wallet = /** @class */ (function () {
    /**
     * @param options Wallet options.
     */
    function Wallet(options) {
        this.methodHandler = new WalletMethodHandler(options);
    }
    /**
     * Backup the data to a Stronghold snapshot.
     */
    Wallet.prototype.backup = function (destination, password) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'backup',
                            data: {
                                destination: destination,
                                password: password
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
     * Change the Stronghold password.
     */
    Wallet.prototype.changeStrongholdPassword = function (currentPassword, newPassword) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'changeStrongholdPassword',
                            data: {
                                currentPassword: currentPassword,
                                newPassword: newPassword
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
     * Clear the Stronghold password from memory.
     */
    Wallet.prototype.clearStrongholdPassword = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'clearStrongholdPassword'
                        })];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * Create a new account.
     */
    Wallet.prototype.createAccount = function (data) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'createAccount',
                            data: data
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, new Account(JSON.parse(response).payload, this.methodHandler)];
                }
            });
        });
    };
    /**
     * Destroy the Wallet and drop its database connection.
     */
    Wallet.prototype.destroy = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.methodHandler.destroy()];
            });
        });
    };
    /**
     * Emit a provided event for testing of the event system.
     */
    Wallet.prototype.emitTestEvent = function (event) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'emitTestEvent',
                            data: { event: event }
                        })];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * Get an account by its alias or index.
     */
    Wallet.prototype.getAccount = function (accountId) {
        return __awaiter(this, void 0, void 0, function () {
            var response, account;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getAccount',
                            data: { accountId: accountId }
                        })];
                    case 1:
                        response = _a.sent();
                        account = new Account(JSON.parse(response).payload, this.methodHandler);
                        return [2 /*return*/, account];
                }
            });
        });
    };
    /**
     * Get all account indexes.
     */
    Wallet.prototype.getAccountIndexes = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getAccountIndexes'
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get all accounts.
     */
    Wallet.prototype.getAccounts = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response, payload, accounts, _i, payload_1, account;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getAccounts'
                        })];
                    case 1:
                        response = _a.sent();
                        payload = JSON.parse(response).payload;
                        accounts = [];
                        for (_i = 0, payload_1 = payload; _i < payload_1.length; _i++) {
                            account = payload_1[_i];
                            accounts.push(new Account(account, this.methodHandler));
                        }
                        return [2 /*return*/, accounts];
                }
            });
        });
    };
    /**
     * Get client.
     */
    Wallet.prototype.getClient = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.methodHandler.getClient()];
            });
        });
    };
    /**
     * Get chrysalis data.
     */
    Wallet.prototype.getChrysalisData = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'getChrysalisData'
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Get secret manager.
     */
    Wallet.prototype.getSecretManager = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.methodHandler.getSecretManager()];
            });
        });
    };
    /**
     * Generate an address without storing it.
     */
    Wallet.prototype.generateEd25519Address = function (accountIndex, addressIndex, options, bech32Hrp) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'generateEd25519Address',
                            data: {
                                accountIndex: accountIndex,
                                addressIndex: addressIndex,
                                options: options,
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
     * Get the status for a Ledger Nano.
     */
    Wallet.prototype.getLedgerNanoStatus = function () {
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
    /**
     * Check if the Stronghold password has been set.
     */
    Wallet.prototype.isStrongholdPasswordAvailable = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'isStrongholdPasswordAvailable'
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Listen to wallet events with a callback. An empty array will listen to all possible events.
     */
    Wallet.prototype.listen = function (eventTypes, callback) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.methodHandler.listen(eventTypes, callback)];
            });
        });
    };
    /**
     * Clear the callbacks for provided events. An empty array will clear all listeners.
     */
    Wallet.prototype.clearListeners = function (eventTypes) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'clearListeners',
                            data: { eventTypes: eventTypes }
                        })];
                    case 1:
                        response = _a.sent();
                        return [2 /*return*/, JSON.parse(response).payload];
                }
            });
        });
    };
    /**
     * Find accounts with unspent outputs.
     */
    Wallet.prototype.recoverAccounts = function (accountStartIndex, accountGapLimit, addressGapLimit, syncOptions) {
        return __awaiter(this, void 0, void 0, function () {
            var response, accounts, _i, _a, account;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'recoverAccounts',
                            data: {
                                accountStartIndex: accountStartIndex,
                                accountGapLimit: accountGapLimit,
                                addressGapLimit: addressGapLimit,
                                syncOptions: syncOptions
                            }
                        })];
                    case 1:
                        response = _b.sent();
                        accounts = [];
                        for (_i = 0, _a = JSON.parse(response).payload; _i < _a.length; _i++) {
                            account = _a[_i];
                            accounts.push(new Account(account, this.methodHandler));
                        }
                        return [2 /*return*/, accounts];
                }
            });
        });
    };
    /**
     * Delete the latest account.
     */
    Wallet.prototype.removeLatestAccount = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'removeLatestAccount'
                        })];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * Restore a backup from a Stronghold file
     * Replaces client_options, coin_type, secret_manager and accounts. Returns an error if accounts were already created
     * If Stronghold is used as secret_manager, the existing Stronghold file will be overwritten. If a mnemonic was
     * stored, it will be gone.
     * if ignore_if_coin_type_mismatch is provided client options will not be restored
     * if ignore_if_coin_type_mismatch == true, client options coin type and accounts will not be restored if the cointype doesn't match
     * if ignore_if_bech32_hrp_mismatch == Some("rms"), but addresses have something different like "smr", no accounts
     * will be restored.
     */
    Wallet.prototype.restoreBackup = function (source, password, ignoreIfCoinTypeMismatch, ignoreIfBech32Mismatch) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'restoreBackup',
                            data: {
                                source: source,
                                password: password,
                                ignoreIfCoinTypeMismatch: ignoreIfCoinTypeMismatch,
                                ignoreIfBech32Mismatch: ignoreIfBech32Mismatch
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
     * Set ClientOptions.
     */
    Wallet.prototype.setClientOptions = function (clientOptions) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'setClientOptions',
                            data: { clientOptions: clientOptions }
                        })];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * Set the Stronghold password.
     */
    Wallet.prototype.setStrongholdPassword = function (password) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'setStrongholdPassword',
                            data: { password: password }
                        })];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * Set the interval after which the Stronghold password gets cleared from memory.
     */
    Wallet.prototype.setStrongholdPasswordClearInterval = function (intervalInMilliseconds) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'setStrongholdPasswordClearInterval',
                            data: { intervalInMilliseconds: intervalInMilliseconds }
                        })];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * Start the background syncing process for all accounts.
     */
    Wallet.prototype.startBackgroundSync = function (options, intervalInMilliseconds) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'startBackgroundSync',
                            data: {
                                options: options,
                                intervalInMilliseconds: intervalInMilliseconds
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
     * Stop the background syncing process for all accounts.
     */
    Wallet.prototype.stopBackgroundSync = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'stopBackgroundSync'
                        })];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * Store a mnemonic in the Stronghold snapshot.
     */
    Wallet.prototype.storeMnemonic = function (mnemonic) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'storeMnemonic',
                            data: { mnemonic: mnemonic }
                        })];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    /**
     * Update the authentication for the provided node.
     */
    Wallet.prototype.updateNodeAuth = function (url, auth) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, this.methodHandler.callMethod({
                            name: 'updateNodeAuth',
                            data: { url: url, auth: auth }
                        })];
                    case 1:
                        _a.sent();
                        return [2 /*return*/];
                }
            });
        });
    };
    return Wallet;
}());
export { Wallet };
//# sourceMappingURL=wallet.js.map