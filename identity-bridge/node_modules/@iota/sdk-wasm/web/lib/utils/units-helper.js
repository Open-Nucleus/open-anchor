// Copyright 2020 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
/**
 * Class to help with units formatting.
 */
var UnitsHelper = /** @class */ (function () {
    function UnitsHelper() {
    }
    /**
     * Format the value in the best units.
     * @param value The value to format.
     * @param decimalPlaces The number of decimal places to display.
     * @returns The formatted value.
     */
    UnitsHelper.formatBest = function (value, decimalPlaces) {
        if (decimalPlaces === void 0) { decimalPlaces = 2; }
        return UnitsHelper.formatUnits(value, UnitsHelper.calculateBest(value), decimalPlaces);
    };
    /**
     * Format the value in the best units.
     * @param value The value to format.
     * @param magnitude The magnitude to format with.
     * @param decimalPlaces The number of decimal places to display.
     * @returns The formatted value.
     */
    UnitsHelper.formatUnits = function (value, magnitude, decimalPlaces) {
        if (decimalPlaces === void 0) { decimalPlaces = 2; }
        if (!UnitsHelper.MAGNITUDE_MAP[magnitude]) {
            throw new Error("Unrecognized magnitude ".concat(magnitude));
        }
        if (!value) {
            return '0';
        }
        return magnitude === ''
            ? "".concat(value)
            : "".concat(UnitsHelper.convertUnits(value, '', magnitude).toFixed(decimalPlaces), " ").concat(magnitude);
    };
    /**
     * Format the value in the best units.
     * @param value The value to format.
     * @returns The best units for the value.
     */
    UnitsHelper.calculateBest = function (value) {
        var bestUnits = '';
        if (!value) {
            return bestUnits;
        }
        var checkLength = Math.abs(value).toString().length;
        if (checkLength > UnitsHelper.MAGNITUDE_MAP.P.dp) {
            bestUnits = 'P';
        }
        else if (checkLength > UnitsHelper.MAGNITUDE_MAP.T.dp) {
            bestUnits = 'T';
        }
        else if (checkLength > UnitsHelper.MAGNITUDE_MAP.G.dp) {
            bestUnits = 'G';
        }
        else if (checkLength > UnitsHelper.MAGNITUDE_MAP.M.dp) {
            bestUnits = 'M';
        }
        else if (checkLength > UnitsHelper.MAGNITUDE_MAP.K.dp) {
            bestUnits = 'K';
        }
        return bestUnits;
    };
    /**
     * Convert the value to different units.
     * @param value The value to convert.
     * @param from The from magnitude.
     * @param to The to magnitude.
     * @returns The formatted unit.
     */
    UnitsHelper.convertUnits = function (value, from, to) {
        if (!value) {
            return 0;
        }
        if (!UnitsHelper.MAGNITUDE_MAP[from]) {
            throw new Error("Unrecognized fromUnit ".concat(from));
        }
        if (!UnitsHelper.MAGNITUDE_MAP[to]) {
            throw new Error("Unrecognized toUnit ".concat(to));
        }
        if (from === to) {
            return Number(value);
        }
        var multiplier = value < 0 ? -1 : 1;
        var scaledValue = (Math.abs(Number(value)) * UnitsHelper.MAGNITUDE_MAP[from].val) /
            UnitsHelper.MAGNITUDE_MAP[to].val;
        var numDecimals = UnitsHelper.MAGNITUDE_MAP[to].dp;
        // We cant use toFixed to just convert the new value to a string with
        // fixed decimal places as it will round, which we don't want
        // instead we want to convert the value to a string and manually
        // truncate the number of digits after the decimal
        // Unfortunately large numbers end up in scientific notation with
        // the regular toString() so we use a custom conversion.
        var fixed = scaledValue.toString();
        if (fixed.includes('e')) {
            fixed = scaledValue.toFixed(Number.parseInt(fixed.split('-')[1], 10));
        }
        // Now we have the number as a full string we can split it into
        // whole and decimals parts
        var parts = fixed.split('.');
        if (parts.length === 1) {
            parts.push('0');
        }
        // Now truncate the decimals by the number allowed on the toUnit
        parts[1] = parts[1].slice(0, numDecimals);
        // Finally join the parts and convert back to a real number
        return Number.parseFloat("".concat(parts[0], ".").concat(parts[1])) * multiplier;
    };
    /**
     * Map units.
     */
    UnitsHelper.MAGNITUDE_MAP = {
        '': { val: 1, dp: 0 },
        K: { val: 1000, dp: 3 },
        M: { val: 1000000, dp: 6 },
        G: { val: 1000000000, dp: 9 },
        T: { val: 1000000000000, dp: 12 },
        P: { val: 1000000000000000, dp: 15 }
    };
    return UnitsHelper;
}());
export { UnitsHelper };
//# sourceMappingURL=units-helper.js.map