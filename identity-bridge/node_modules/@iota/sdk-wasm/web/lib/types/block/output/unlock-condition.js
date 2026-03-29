// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
import { plainToInstance, Type } from 'class-transformer';
import { Address, AddressDiscriminator } from '../address';
/**
 * All of the unlock condition types.
 */
var UnlockConditionType;
(function (UnlockConditionType) {
    /** An address unlock condition. */
    UnlockConditionType[UnlockConditionType["Address"] = 0] = "Address";
    /** A storage deposit return unlock condition. */
    UnlockConditionType[UnlockConditionType["StorageDepositReturn"] = 1] = "StorageDepositReturn";
    /** A timelock unlock condition. */
    UnlockConditionType[UnlockConditionType["Timelock"] = 2] = "Timelock";
    /** An expiration unlock condition. */
    UnlockConditionType[UnlockConditionType["Expiration"] = 3] = "Expiration";
    /** A state controller address unlock condition. */
    UnlockConditionType[UnlockConditionType["StateControllerAddress"] = 4] = "StateControllerAddress";
    /** A governor address unlock condition. */
    UnlockConditionType[UnlockConditionType["GovernorAddress"] = 5] = "GovernorAddress";
    /** An immutable alias address unlock condition. */
    UnlockConditionType[UnlockConditionType["ImmutableAliasAddress"] = 6] = "ImmutableAliasAddress";
})(UnlockConditionType || (UnlockConditionType = {}));
var UnlockCondition = /** @class */ (function () {
    /**
     * @param type The type of the unlock condition.
     */
    function UnlockCondition(type) {
        this.type = type;
    }
    /**
     * Get the type of unlock condition.
     */
    UnlockCondition.prototype.getType = function () {
        return this.type;
    };
    /**
     * Parse an unlock condition from a plain JS JSON object.
     */
    UnlockCondition.parse = function (data) {
        if (data.type == UnlockConditionType.Address) {
            return plainToInstance(AddressUnlockCondition, data);
        }
        else if (data.type == UnlockConditionType.StorageDepositReturn) {
            return plainToInstance(StorageDepositReturnUnlockCondition, data);
        }
        else if (data.type == UnlockConditionType.Timelock) {
            return plainToInstance(TimelockUnlockCondition, data);
        }
        else if (data.type == UnlockConditionType.Expiration) {
            return plainToInstance(ExpirationUnlockCondition, data);
        }
        else if (data.type == UnlockConditionType.StateControllerAddress) {
            return plainToInstance(StateControllerAddressUnlockCondition, data);
        }
        else if (data.type == UnlockConditionType.GovernorAddress) {
            return plainToInstance(GovernorAddressUnlockCondition, data);
        }
        else if (data.type == UnlockConditionType.ImmutableAliasAddress) {
            return plainToInstance(ImmutableAliasAddressUnlockCondition, data);
        }
        throw new Error('Invalid JSON');
    };
    return UnlockCondition;
}());
/**
 * An address unlock condition.
 */
var AddressUnlockCondition = /** @class */ (function (_super) {
    __extends(AddressUnlockCondition, _super); /*implements IAddressUnlockCondition*/
    /**
     * @param address The address that needs to be unlocked with a private key.
     */
    function AddressUnlockCondition(address) {
        var _this = _super.call(this, UnlockConditionType.Address) || this;
        _this.address = address;
        return _this;
    }
    /**
     * Get the address.
     */
    AddressUnlockCondition.prototype.getAddress = function () {
        return this.address;
    };
    __decorate([
        Type(function () { return Address; }, {
            discriminator: AddressDiscriminator
        })
    ], AddressUnlockCondition.prototype, "address");
    return AddressUnlockCondition;
}(UnlockCondition /*implements IAddressUnlockCondition*/));
/**
 * A Storage Deposit Return Unlock Condition.
 */
var StorageDepositReturnUnlockCondition = /** @class */ (function (_super) {
    __extends(StorageDepositReturnUnlockCondition, _super); /*implements IStorageDepositReturnUnlockCondition*/
    /**
     * @param returnAddress The address to return the amount to.
     * @param amount The amount the consuming transaction must deposit to `returnAddress`.
     */
    function StorageDepositReturnUnlockCondition(returnAddress, amount) {
        var _this = _super.call(this, UnlockConditionType.StorageDepositReturn) || this;
        if (typeof amount == 'bigint') {
            _this.amount = amount.toString(10);
        }
        else {
            _this.amount = amount;
        }
        _this.returnAddress = returnAddress;
        return _this;
    }
    /**
     * Get the amount.
     */
    StorageDepositReturnUnlockCondition.prototype.getAmount = function () {
        return BigInt(this.amount);
    };
    /**
     * Get the return address.
     */
    StorageDepositReturnUnlockCondition.prototype.getReturnAddress = function () {
        return this.returnAddress;
    };
    __decorate([
        Type(function () { return Address; }, {
            discriminator: AddressDiscriminator
        })
    ], StorageDepositReturnUnlockCondition.prototype, "returnAddress");
    return StorageDepositReturnUnlockCondition;
}(UnlockCondition /*implements IStorageDepositReturnUnlockCondition*/));
/**
 * A Timelock Unlock Condition.
 */
var TimelockUnlockCondition = /** @class */ (function (_super) {
    __extends(TimelockUnlockCondition, _super); /*implements ITimelockUnlockCondition*/
    /**
     * @param unixTime The Unix timestamp marking the end of the timelock.
     */
    function TimelockUnlockCondition(unixTime) {
        var _this = _super.call(this, UnlockConditionType.Timelock) || this;
        _this.unixTime = unixTime;
        return _this;
    }
    /**
     * Get the end of the timelock as Unix time.
     */
    TimelockUnlockCondition.prototype.getUnixTime = function () {
        return this.unixTime;
    };
    return TimelockUnlockCondition;
}(UnlockCondition /*implements ITimelockUnlockCondition*/));
/**
 * An Expiration Unlock Condition.
 */
var ExpirationUnlockCondition = /** @class */ (function (_super) {
    __extends(ExpirationUnlockCondition, _super); /*implements IExpirationUnlockCondition*/
    /**
     * @param returnAddress The address that can unlock the expired output.
     * @param unixTime The Unix timestamp marking the end of the claim period.
     */
    function ExpirationUnlockCondition(returnAddress, unixTime) {
        var _this = _super.call(this, UnlockConditionType.Expiration) || this;
        _this.returnAddress = returnAddress;
        _this.unixTime = unixTime;
        return _this;
    }
    /**
     * Get the end of the expiration period as Unix time.
     */
    ExpirationUnlockCondition.prototype.getUnixTime = function () {
        return this.unixTime;
    };
    /**
     * Get the return address.
     */
    ExpirationUnlockCondition.prototype.getReturnAddress = function () {
        return this.returnAddress;
    };
    __decorate([
        Type(function () { return Address; }, {
            discriminator: AddressDiscriminator
        })
    ], ExpirationUnlockCondition.prototype, "returnAddress");
    return ExpirationUnlockCondition;
}(UnlockCondition /*implements IExpirationUnlockCondition*/));
/**
 * A State Controller Address Unlock Condition.
 */
var StateControllerAddressUnlockCondition = /** @class */ (function (_super) {
    __extends(StateControllerAddressUnlockCondition, _super); /*implements IStateControllerAddressUnlockCondition*/
    /**
     * @param address The State Controller address that is allowed to do state transitions.
     */
    function StateControllerAddressUnlockCondition(address) {
        var _this = _super.call(this, UnlockConditionType.StateControllerAddress) || this;
        _this.address = address;
        return _this;
    }
    /**
     * Get the State Controller address.
     */
    StateControllerAddressUnlockCondition.prototype.getAddress = function () {
        return this.address;
    };
    __decorate([
        Type(function () { return Address; }, {
            discriminator: AddressDiscriminator
        })
    ], StateControllerAddressUnlockCondition.prototype, "address");
    return StateControllerAddressUnlockCondition;
}(UnlockCondition /*implements IStateControllerAddressUnlockCondition*/));
/**
 * A Governor Address Unlock Condition.
 */
var GovernorAddressUnlockCondition = /** @class */ (function (_super) {
    __extends(GovernorAddressUnlockCondition, _super); /*implements IGovernorAddressUnlockCondition*/
    /**
     * @param address The governor address that is allowed to do governance transitions.
     */
    function GovernorAddressUnlockCondition(address) {
        var _this = _super.call(this, UnlockConditionType.GovernorAddress) || this;
        _this.address = address;
        return _this;
    }
    /**
     * Get the Governor address.
     */
    GovernorAddressUnlockCondition.prototype.getAddress = function () {
        return this.address;
    };
    __decorate([
        Type(function () { return Address; }, {
            discriminator: AddressDiscriminator
        })
    ], GovernorAddressUnlockCondition.prototype, "address");
    return GovernorAddressUnlockCondition;
}(UnlockCondition /*implements IGovernorAddressUnlockCondition*/));
/**
 * An Immutable Alias Address Unlock Condition.
 */
var ImmutableAliasAddressUnlockCondition = /** @class */ (function (_super) {
    __extends(ImmutableAliasAddressUnlockCondition, _super); /*implements IImmutableAliasAddressUnlockCondition*/
    /**
     * @param address The Immutable Alias address that owns the output.
     */
    function ImmutableAliasAddressUnlockCondition(address) {
        var _this = _super.call(this, UnlockConditionType.ImmutableAliasAddress) || this;
        _this.address = address;
        return _this;
    }
    /**
     * Get the Immutable Alias address.
     */
    ImmutableAliasAddressUnlockCondition.prototype.getAddress = function () {
        return this.address;
    };
    __decorate([
        Type(function () { return Address; }, {
            discriminator: AddressDiscriminator
        })
    ], ImmutableAliasAddressUnlockCondition.prototype, "address");
    return ImmutableAliasAddressUnlockCondition;
}(UnlockCondition /*implements IImmutableAliasAddressUnlockCondition*/));
var UnlockConditionDiscriminator = {
    property: 'type',
    subTypes: [
        {
            value: AddressUnlockCondition,
            name: UnlockConditionType.Address
        },
        {
            value: StorageDepositReturnUnlockCondition,
            name: UnlockConditionType.StorageDepositReturn
        },
        {
            value: TimelockUnlockCondition,
            name: UnlockConditionType.Timelock
        },
        {
            value: ExpirationUnlockCondition,
            name: UnlockConditionType.Expiration
        },
        {
            value: StateControllerAddressUnlockCondition,
            name: UnlockConditionType.StateControllerAddress
        },
        {
            value: GovernorAddressUnlockCondition,
            name: UnlockConditionType.GovernorAddress
        },
        {
            value: ImmutableAliasAddressUnlockCondition,
            name: UnlockConditionType.ImmutableAliasAddress
        },
    ]
};
export { UnlockConditionDiscriminator, UnlockCondition, UnlockConditionType, AddressUnlockCondition, StorageDepositReturnUnlockCondition, TimelockUnlockCondition, ExpirationUnlockCondition, StateControllerAddressUnlockCondition, GovernorAddressUnlockCondition, ImmutableAliasAddressUnlockCondition, };
//# sourceMappingURL=unlock-condition.js.map