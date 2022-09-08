import {cryptoWaitReady} from '@polkadot/util-crypto'
import {KeyringPair} from '@polkadot/keyring/types'
import {ApiPromise, Keyring, WsProvider} from '@polkadot/api'
import {TypeRegistry} from '@polkadot/types'
import {Metadata} from '@polkadot/types/metadata';
import {BN, u8aToHex, hexToU8a} from '@polkadot/util'
import type {KeyObject} from 'crypto'
import {createPublicKey, publicEncrypt} from 'crypto'
import * as jose from 'jose'
import {definitions} from "./type-definitions";
import {Codec} from "@polkadot/types/types";

const base58 = require('micro-base58');

const WebSocketAsPromised = require('websocket-as-promised');
const WebSocket = require('ws');
const keyring = new Keyring({type: 'sr25519'})
const NodeRSA = require('node-rsa');

// in order to handle self-signed certificates we need to turn off the validation
// TODO add self signed certificate ??
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

type WorkerRpcReturnValue = {
	value: `0x${string}`
	do_watch: boolean
	status: string
}

type WorkerRpcReturnString = {
	vec: string
}

type PubicKeyJson = {
	n: Uint8Array,
	e: Uint8Array
}

function toBalance(amountInt: number) {
	return new BN(amountInt).mul(new BN(10).pow(new BN(12)))
}

async function sendRequest(wsClient: any, request: any, api: ApiPromise): Promise<WorkerRpcReturnValue> {
	const resp = await wsClient.sendRequest(request, {requestId: 1, timeout: 6000})
	const resp_json = api.createType("WorkerRpcReturnValue", resp.result).toJSON() as WorkerRpcReturnValue
	return resp_json
}


export const createTrustedCall = (parachain_api: ApiPromise, trustedCall: [string, string], account: KeyringPair, mrenclave: string, shard: string, nonce: Codec, params: Array<any>) => {
	const [variant, argType] = trustedCall;
	const call = parachain_api.createType('TrustedCall', {
		[variant]: parachain_api.createType(argType, params)
	});
	const payload = Uint8Array.from([...call.toU8a(), ...nonce.toU8a(), ...base58.decode(mrenclave), ...hexToU8a(shard)]);
	const signature = parachain_api.createType('MultiSignature', {
		"Sr25519": u8aToHex(account.sign(payload))
	})
	return parachain_api.createType('TrustedCallSigned', {
		call: call,
		index: nonce,
		signature: signature
	});
};

async function createTransferTrustedCall(parachain_api: ApiPromise, account: KeyringPair, to: string, mrenclave: string, shard: `0x${string}`, amount: BN): Promise<Uint8Array> {
	//TODO get nonce from worker rpc
	const nonce = parachain_api.createType('Index', '0x01');
	const call = createTrustedCall(
		parachain_api,
		['balance_transfer', '(AccountId, AccountId, Balance)'],
		account,
		mrenclave,
		shard,
		nonce,
		[account.address, to, amount]
	);
	const trustedOperation = parachain_api.createType('TrustedOperation', {'indirect_call': call})
	return trustedOperation.toU8a()
}

async function test() {
	const provider = new WsProvider('ws://integritee-node:9912')
	const registry = new TypeRegistry()
	const parachain_api = await ApiPromise.create({
		provider, types: definitions
	})
	await cryptoWaitReady()
	const wsp = new WebSocketAsPromised('wss://localhost:2000', {
		createWebSocket: (url: any) => new WebSocket(url),
		extractMessageData: (event: any) => event, // <- this is important
		packMessage: (data: any) => JSON.stringify(data),
		unpackMessage: (data: string) => JSON.parse(data),
		attachRequestId: (data: any, requestId: string | number) => Object.assign({id: requestId}, data), // attach requestId to message as `id` field
		extractRequestId: (data: any) => data && data.id,                                  // read requestId from message `id` field
	});
	await wsp.open()

	let request = {jsonrpc: "2.0", method: "author_getShieldingKey", params: [], id: 1};
	let respJSON = await sendRequest(wsp, request, parachain_api)
	const pubKeyHex = parachain_api.createType("WorkerRpcReturnString", respJSON.value).toJSON() as WorkerRpcReturnString
	let chunk = Buffer.from(pubKeyHex.vec.slice(2), 'hex');
	const pubKeyJSON = JSON.parse(chunk.toString("utf-8")) as PubicKeyJson

	// request = {jsonrpc: "2.0", method: "state_getMetadata", params: [], id: 1};
	// respJSON = await sendRequest(wsp, request, parachain_api)
	// const metadata = new Metadata(registry, respJSON.value)

	// const key = new NodeRSA();
	// key.setOptions(
	// 	{
	// 		encryptionScheme: {
	// 			scheme: 'pkcs1_oaep',
	// 			hash: 'sha256',
	// 			label: ''
	// 		}
	// 	}
	// );
	// key.importKey({
	// 	"n": Buffer.from(pubKeyJSON.n),
	// 	"e": 16777217
	// }, 'components-public');
	// let tmp1 = key.encrypt(u8aToHex(new Uint8Array([1, 2, 3, 4])), 'buffer', 'hex')

	const pubKeyObj = createPublicKey({
		key: {
			"alg": "RSA-OAEP",
			"kty": "RSA",
			"use": "enc",
			n: jose.base64url.encode(Buffer.from(pubKeyJSON.n)),
			e: jose.base64url.encode(Buffer.from('01000001', 'hex')),
		},
		format: "jwk"
	})

	const alice: KeyringPair = keyring.addFromUri('//Alice', {name: 'Alice'})
	const bob_stash = keyring.addFromUri('//Bob//stash', {name: 'Bob_stash'})

	//could
	const mrenclave = 'AaYrAiZhVXLrgnWyidns1hPRBF7iozMT5z6eMSzVBVod'
	const shard = '0x8e515bff464371ef8b6cf7305018d3b4365dca04e8403d516b7e6836eea057b0'
	const call = await createTransferTrustedCall(parachain_api, alice, bob_stash.address, mrenclave, shard, toBalance(10))
	const cyphertext = publicEncrypt(pubKeyObj, call)
	// const request2 = {jsonrpc: "2.0", method: "test_encrypt", params: Array.prototype.slice.call(cyphertext), id: 1};

	// const encryptResp = await sendRequest(wsp, {
	// 	jsonrpc: "2.0",
	// 	method: "test_encrypt",
	// 	params: Array.from(call),
	// 	id: 1
	// }, parachain_api)
	console.log(`0x${cyphertext.toString('hex')}`)
	await parachain_api.tx.teerex.callWorker({
		shard: shard,
		cyphertext: `0x${cyphertext.toString('hex')}`
	}).signAndSend(alice)


	// function unpack(str: string): Uint8Array {
	// 	var bytes = [];
	// 	for (var i = 0; i < str.length; i++) {
	// 		var char = str.charCodeAt(i);
	// 		bytes.push(char >>> 8);
	// 		bytes.push(char & 0xFF);
	// 	}
	// 	return new Uint8Array(bytes);
	// }
	// console.log("======")
	// console.log("test encrypt 2:", u8aToHex(publicEncrypt(pubKeyObj, new Uint8Array([1, 2, 3, 4]))))
}


(async () => {
	// await transferLITFromETHToParachain()
	await test().catch(e => {
		console.error(e)
	})
	process.exit(0)
})()
