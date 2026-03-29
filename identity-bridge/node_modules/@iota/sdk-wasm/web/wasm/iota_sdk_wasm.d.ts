/* tslint:disable */
/* eslint-disable */
/**
* Creates a method handler with the given client options.
* @param {string} clientOptions
* @returns {ClientMethodHandler}
*/
export function createClient(clientOptions: string): ClientMethodHandler;
/**
* Necessary for compatibility with the node.js bindings.
* @param {ClientMethodHandler} _client_method_handler
* @returns {Promise<void>}
*/
export function destroyClient(_client_method_handler: ClientMethodHandler): Promise<void>;
/**
* Handles a method, returns the response as a JSON-encoded string.
*
* Returns an error if the response itself is an error or panic.
* @param {string} method
* @param {ClientMethodHandler} methodHandler
* @returns {Promise<string>}
*/
export function callClientMethodAsync(method: string, methodHandler: ClientMethodHandler): Promise<string>;
/**
* MQTT is not supported for WebAssembly bindings.
*
* Throws an error if called, only included for compatibility
* with the Node.js bindings TypeScript definitions.
* @param {string[]} _topics
* @param {Function} _callback
*/
export function listenMqtt(_topics: string[], _callback: Function): void;
/**
* Creates a method handler with the given secret_manager options.
* @param {string} options
* @returns {SecretManagerMethodHandler}
*/
export function createSecretManager(options: string): SecretManagerMethodHandler;
/**
* Handles a method, returns the response as a JSON-encoded string.
*
* Returns an error if the response itself is an error or panic.
* @param {string} method
* @param {SecretManagerMethodHandler} methodHandler
* @returns {Promise<string>}
*/
export function callSecretManagerMethodAsync(method: string, methodHandler: SecretManagerMethodHandler): Promise<string>;
/**
* Stronghold snapshot migration is not supported for WebAssembly bindings.
*
* Throws an error if called, only included for compatibility
* with the Node.js bindings TypeScript definitions.
* @param {string} _current_path
* @param {string} _current_password
* @param {string} _salt
* @param {number} _rounds
* @param {string | undefined} [_new_path]
* @param {string | undefined} [_new_password]
*/
export function migrateStrongholdSnapshotV2ToV3(_current_path: string, _current_password: string, _salt: string, _rounds: number, _new_path?: string, _new_password?: string): void;
/**
* Handles a method, returns the response as a JSON-encoded string.
*
* Returns an error if the response itself is an error or panic.
* @param {string} method
* @returns {any}
*/
export function callUtilsMethodRust(method: string): any;
/**
* Creates a method handler with the given options.
* @param {string} options
* @returns {WalletMethodHandler}
*/
export function createWallet(options: string): WalletMethodHandler;
/**
* @param {WalletMethodHandler} method_handler
* @returns {Promise<void>}
*/
export function destroyWallet(method_handler: WalletMethodHandler): Promise<void>;
/**
* @param {WalletMethodHandler} method_handler
* @returns {Promise<ClientMethodHandler>}
*/
export function getClientFromWallet(method_handler: WalletMethodHandler): Promise<ClientMethodHandler>;
/**
* @param {WalletMethodHandler} method_handler
* @returns {Promise<SecretManagerMethodHandler>}
*/
export function getSecretManagerFromWallet(method_handler: WalletMethodHandler): Promise<SecretManagerMethodHandler>;
/**
* Handles a method, returns the response as a JSON-encoded string.
*
* Returns an error if the response itself is an error or panic.
* @param {string} method
* @param {WalletMethodHandler} method_handler
* @returns {Promise<string>}
*/
export function callWalletMethodAsync(method: string, method_handler: WalletMethodHandler): Promise<string>;
/**
* It takes a list of event types, registers a callback function, and then listens for events of those
* types
*
* Arguments:
*
* * `vec`: An array of strings that represent the event types you want to listen to.
* * `callback`: A JavaScript function that will be called when a wallet event occurs.
* * `method_handler`: This is the same method handler that we used in the previous section.
* @param {Array<any>} vec
* @param {Function} callback
* @param {WalletMethodHandler} method_handler
* @returns {Promise<any>}
*/
export function listenWalletAsync(vec: Array<any>, callback: Function, method_handler: WalletMethodHandler): Promise<any>;
/**
* Rocksdb chrysalis migration is not supported for WebAssembly bindings.
*
* Throws an error if called, only included for compatibility
* with the Node.js bindings TypeScript definitions.
* @param {string} _storage_path
* @param {string | undefined} [_password]
*/
export function migrateDbChrysalisToStardust(_storage_path: string, _password?: string): void;
/**
* Initializes the console error panic hook for better panic messages.
* Gets automatically called when using wasm
*/
export function start(): void;
/**
* The Wasm bindings do not support internal logging configuration yet.
*
* Calling this will enable all rust logs to be show
* @param {string} _config
* @returns {Promise<void>}
*/
export function initLogger(_config: string): Promise<void>;
/**
* The Client method handler.
*/
export class ClientMethodHandler {
  free(): void;
}
/**
* The SecretManager method handler.
*/
export class SecretManagerMethodHandler {
  free(): void;
}
/**
* The Wallet method handler.
*/
export class WalletMethodHandler {
  free(): void;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_clientmethodhandler_free: (a: number) => void;
  readonly createClient: (a: number, b: number, c: number) => void;
  readonly destroyClient: (a: number) => number;
  readonly callClientMethodAsync: (a: number, b: number, c: number, d: number) => void;
  readonly listenMqtt: (a: number, b: number, c: number) => void;
  readonly __wbg_secretmanagermethodhandler_free: (a: number) => void;
  readonly createSecretManager: (a: number, b: number, c: number) => void;
  readonly callSecretManagerMethodAsync: (a: number, b: number, c: number, d: number) => void;
  readonly migrateStrongholdSnapshotV2ToV3: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number) => void;
  readonly callUtilsMethodRust: (a: number, b: number, c: number) => void;
  readonly __wbg_walletmethodhandler_free: (a: number) => void;
  readonly createWallet: (a: number, b: number, c: number) => void;
  readonly destroyWallet: (a: number) => number;
  readonly getClientFromWallet: (a: number) => number;
  readonly getSecretManagerFromWallet: (a: number) => number;
  readonly callWalletMethodAsync: (a: number, b: number, c: number) => number;
  readonly listenWalletAsync: (a: number, b: number, c: number) => number;
  readonly migrateDbChrysalisToStardust: (a: number, b: number, c: number, d: number, e: number) => void;
  readonly start: () => void;
  readonly initLogger: (a: number, b: number) => number;
  readonly __wbindgen_export_0: (a: number, b: number) => number;
  readonly __wbindgen_export_1: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_export_2: WebAssembly.Table;
  readonly __wbindgen_export_3: (a: number, b: number) => void;
  readonly __wbindgen_export_4: (a: number, b: number, c: number) => void;
  readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
  readonly __wbindgen_export_5: (a: number, b: number, c: number) => void;
  readonly __wbindgen_export_6: (a: number) => void;
  readonly __wbindgen_export_7: (a: number, b: number, c: number, d: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {SyncInitInput} module
*
* @returns {InitOutput}
*/
export function initSync(module: SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {InitInput | Promise<InitInput>} module_or_path
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: InitInput | Promise<InitInput>): Promise<InitOutput>;

/**
* Loads the Wasm file so the lib can be used, relative path to Wasm file
*
* @param {string | undefined} path
*/
export function init(path?: string): Promise<void>;