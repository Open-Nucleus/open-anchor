// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
/**
 * All of the milestone option types.
 */
var MilestoneOptionType;
(function (MilestoneOptionType) {
    /** The Receipt milestone option. */
    MilestoneOptionType[MilestoneOptionType["Receipt"] = 0] = "Receipt";
    /** The ProtocolParams milestone option. */
    MilestoneOptionType[MilestoneOptionType["ProtocolParams"] = 1] = "ProtocolParams";
})(MilestoneOptionType || (MilestoneOptionType = {}));
var MilestoneOption = /** @class */ (function () {
    /**
     * @param type The type of milestone option.
     */
    function MilestoneOption(type) {
        this.type = type;
    }
    /**
     * Get the type of milestone option.
     */
    MilestoneOption.prototype.getType = function () {
        return this.type;
    };
    return MilestoneOption;
}());
export { MilestoneOptionType, MilestoneOption };
//# sourceMappingURL=milestone-options.js.map