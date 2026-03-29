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
import { callWalletMethodAsync, createWallet, listenWalletAsync, destroyWallet, getClientFromWallet, getSecretManagerFromWallet, } from '../bindings';
import { Client } from '../client';
import { SecretManager } from '../secret_manager';
// The WalletMethodHandler class interacts with methods with the rust bindings.
var WalletMethodHandler = /** @class */ (function () {
    /**
     * @param options The wallet options.
     */
    function WalletMethodHandler(options) {
        var walletOptions = {
            storagePath: options === null || options === void 0 ? void 0 : options.storagePath,
            clientOptions: options === null || options === void 0 ? void 0 : options.clientOptions,
            coinType: options === null || options === void 0 ? void 0 : options.coinType,
            secretManager: options === null || options === void 0 ? void 0 : options.secretManager
        };
        this.methodHandler = createWallet(JSON.stringify(walletOptions));
    }
    /**
     * Call a wallet method on the Rust backend.
     *
     * @param method The wallet method to call.
     */
    WalletMethodHandler.prototype.callMethod = function (method) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, callWalletMethodAsync(
                    // mapToObject is required to convert maps to array since they otherwise get serialized as `[{}]` even if not empty
                    JSON.stringify(method, function mapToObject(_key, value) {
                        if (value instanceof Map) {
                            return Object.fromEntries(value);
                        }
                        else {
                            return value;
                        }
                    }), this.methodHandler)["catch"](function (error) {
                        try {
                            if (error.message !== undefined) {
                                error = JSON.parse(error.message).payload;
                            }
                            else {
                                error = JSON.parse(error.toString()).payload;
                            }
                        }
                        catch (e) {
                            console.error(e);
                        }
                        return Promise.reject(error);
                    })];
            });
        });
    };
    /**
     * Call an account method on the Rust backend.
     *
     * @param accountIndex The account index.
     * @param method The account method to call.
     */
    WalletMethodHandler.prototype.callAccountMethod = function (accountIndex, method) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.callMethod({
                        name: 'callAccountMethod',
                        data: {
                            accountId: accountIndex,
                            method: method
                        }
                    })];
            });
        });
    };
    /**
     * Listen to wallet events.
     *
     * @param eventTypes The wallet event types to listen for.
     * @param callback The callback function to call when an event is received.
     */
    WalletMethodHandler.prototype.listen = function (eventTypes, callback) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, listenWalletAsync(eventTypes, callback, this.methodHandler)];
            });
        });
    };
    WalletMethodHandler.prototype.destroy = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, destroyWallet(this.methodHandler)];
            });
        });
    };
    /**
     * Get the client associated with the wallet.
     */
    WalletMethodHandler.prototype.getClient = function () {
        return __awaiter(this, void 0, void 0, function () {
            var _this = this;
            return __generator(this, function (_a) {
                return [2 /*return*/, new Promise(function (resolve, reject) {
                        getClientFromWallet(_this.methodHandler).then(function (result) {
                            if (result.message !== undefined) {
                                reject(JSON.parse(result.message).payload);
                            }
                            else {
                                resolve(new Client(result));
                            }
                        });
                    })];
            });
        });
    };
    /**
     * Get the secret manager associated with the wallet.
     */
    WalletMethodHandler.prototype.getSecretManager = function () {
        return __awaiter(this, void 0, void 0, function () {
            var _this = this;
            return __generator(this, function (_a) {
                return [2 /*return*/, new Promise(function (resolve, reject) {
                        getSecretManagerFromWallet(_this.methodHandler).then(function (result) {
                            if (result.message !== undefined) {
                                reject(JSON.parse(result.message).payload);
                            }
                            else {
                                resolve(new SecretManager(result));
                            }
                        });
                    })];
            });
        });
    };
    return WalletMethodHandler;
}());
export { WalletMethodHandler };
//# sourceMappingURL=wallet-method-handler.js.map