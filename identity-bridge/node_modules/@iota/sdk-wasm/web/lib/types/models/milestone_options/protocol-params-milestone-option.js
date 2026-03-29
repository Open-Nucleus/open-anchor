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
import { MilestoneOption, MilestoneOptionType } from './milestone-options';
/**
 * A Protocol Parameters Milestone Option.
 */
var ProtocolParamsMilestoneOption = /** @class */ (function (_super) {
    __extends(ProtocolParamsMilestoneOption, _super);
    /**
     * @param targetMilestoneIndex The milestone index at which these protocol parameters become active.
     * @param protocolVersion The to be applied protocol version.
     * @param params The protocol parameters in binary form. Hex-encoded with 0x prefix.
     */
    function ProtocolParamsMilestoneOption(targetMilestoneIndex, protocolVersion, params) {
        var _this = _super.call(this, MilestoneOptionType.Receipt) || this;
        _this.targetMilestoneIndex = targetMilestoneIndex;
        _this.protocolVersion = protocolVersion;
        _this.params = params;
        return _this;
    }
    return ProtocolParamsMilestoneOption;
}(MilestoneOption));
export { ProtocolParamsMilestoneOption };
//# sourceMappingURL=protocol-params-milestone-option.js.map