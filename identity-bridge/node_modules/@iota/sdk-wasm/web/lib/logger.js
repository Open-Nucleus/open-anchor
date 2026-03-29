// Copyright 2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0
import { initLogger as initLoggerBinding } from './bindings';
var defaultLoggerConfig = {
    colorEnabled: true,
    name: './iota-sdk.log',
    levelFilter: 'debug'
};
/** Initialize logger, if no arguments are provided a default config will be used. */
export var initLogger = function (config) {
    if (config === void 0) { config = defaultLoggerConfig; }
    return initLoggerBinding(JSON.stringify(config));
};
//# sourceMappingURL=logger.js.map