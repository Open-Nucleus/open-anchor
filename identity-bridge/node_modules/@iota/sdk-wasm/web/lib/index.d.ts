import 'reflect-metadata';
export * from './client';
export * from './secret_manager';
export * from './types';
export * from './utils';
export * from './wallet';
export * from './logger';
import { init } from '../wasm/iota_sdk_wasm';
export default init;
