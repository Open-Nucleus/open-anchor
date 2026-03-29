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
import { Payload, PayloadType } from '../payload';
/**
 * A Tagged Data payload.
 */
var TaggedDataPayload = /** @class */ (function (_super) {
    __extends(TaggedDataPayload, _super);
    /**
     * @param tag A tag as hex-encoded string.
     * @param data Index data as hex-encoded string.
     */
    function TaggedDataPayload(tag, data) {
        var _this = _super.call(this, PayloadType.TaggedData) || this;
        _this.tag = tag;
        _this.data = data;
        return _this;
    }
    return TaggedDataPayload;
}(Payload));
export { TaggedDataPayload };
//# sourceMappingURL=tagged.js.map