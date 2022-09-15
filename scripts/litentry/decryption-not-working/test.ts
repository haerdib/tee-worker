import { cryptoWaitReady } from '@polkadot/util-crypto'
import { KeyringPair } from '@polkadot/keyring/types'
import { ApiPromise, Keyring, WsProvider } from '@polkadot/api'
import { TypeRegistry, Bytes } from '@polkadot/types'
import { Metadata } from '@polkadot/types/metadata';
import { BN, u8aToHex, hexToU8a, u8aToBuffer, u8aToString, compactAddLength, bufferToU8a } from '@polkadot/util'
import type { KeyObject } from 'crypto'
import { createPublicKey, publicEncrypt } from 'crypto'
import * as jose from 'jose'
import { definitions } from "./type-definitions";
import { Codec } from "@polkadot/types/types";

const base58 = require('micro-base58');

const WebSocketAsPromised = require('websocket-as-promised');
const WebSocket = require('ws');
const keyring = new Keyring({ type: 'sr25519' })
const NodeRSA = require('node-rsa');

// in order to handle self-signed certificates we need to turn off the validation
// TODO add self signed certificate ??
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";


type WorkerRpcReturnValue = {
	value: Uint8Array
	do_watch: boolean
	status: string
}

type WorkerRpcReturnString = {
	vec: string
}

type RsaPublicKey = {
	n: Uint8Array,
	e: Uint8Array
}


type PubicKeyJson = {
	n: Uint8Array,
	e: Uint8Array
}

function toBalance(amountInt: number) {
	return new BN(amountInt).mul(new BN(10).pow(new BN(12)))
}

async function sendRequest(wsClient: any, request: any, api: ApiPromise) {
	const resp = await wsClient.sendRequest(request, { requestId: 1, timeout: 6000 })
	console.log("Immediate resp" + resp.result)
	const resp_json = api.createType("WorkerRpcReturnValue", resp.result)
	console.log("WorkerRpcReturnValue" + resp_json)
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
	const trustedOperation = parachain_api.createType('TrustedOperation', { 'indirect_call': call })
	console.log(trustedOperation);
	return trustedOperation.toU8a()
}

async function test() {
	const provider = new WsProvider('ws://127.0.0.1:9994')
	const registry = new TypeRegistry()
	const parachain_api = await ApiPromise.create({
		provider, types: definitions
	})
	await cryptoWaitReady()
	const wsp = new WebSocketAsPromised('wss://127.0.0.1:2094', {
		createWebSocket: (url: any) => new WebSocket(url),
		extractMessageData: (event: any) => event, // <- this is important
		packMessage: (data: any) => JSON.stringify(data),
		unpackMessage: (data: string) => JSON.parse(data),
		attachRequestId: (data: any, requestId: string | number) => Object.assign({ id: requestId }, data), // attach requestId to message as `id` field
		extractRequestId: (data: any) => data && data.id,                                  // read requestId from message `id` field
	});
	await wsp.open()

	let request = { jsonrpc: "2.0", method: "author_getShieldingKey", params: [], id: 1 };
	let resp = await sendRequest(wsp, request, parachain_api)
	let respJSON = resp.toJSON()
	console.log('value:  ' + respJSON.value)
	const return_value = parachain_api.createType('Vec<u8>', respJSON.value);
	console.log('value  (first two bytes belong to the type registry) \n  ' + return_value.toU8a());
	const decoded_string = parachain_api.createType('String', respJSON.value);
	console.log('value  (first two bytes belong to the type registry) \n  ' + decoded_string);
	//const pubKeyHex = parachain_api.createType("WorkerRpcReturnString", respJSON.value).toJSON() as WorkerRpcReturnString

	//let chunk = Buffer.from(pubKeyHex.vec.slice(2), 'hex');
	//console.log(pubKeyHex.vec.slice(2))
	//console.log(chunk)

	//const keyJson = JSON.parse(respJSON.value.toString("utf-8")) as PubicKeyJson;
	//const keyJson = JSON.parse(chunk.toString("utf-8")) as PubicKeyJson;
	//const keyJson = decoded_string.toJSON();
	//console.log("keyJson n \n" + keyJson.n.toString())
	const keyJson = JSON.parse(decoded_string.toString().slice(2)) as PubicKeyJson;
	console.log("keyJson n \n" + keyJson.n)
	console.log("keyJson e \n" + keyJson.e)
	keyJson.n = u8aToBuffer(keyJson.n);
	keyJson.e = u8aToBuffer(keyJson.e);
	///keyJson.e = Buffer.from(keyJson.e, 'base64');

	console.log("keyJson n \n" + u8aToHex(keyJson.n))
	console.log("keyJson e \n" + u8aToHex(keyJson.e))
	//const pubKeyJSON = JSON.parse(chunk.toString("utf-8")) as PubicKeyJson

	// request = {jsonrpc: "2.0", method: "state_getMetadata", params: [], id: 1};
	// respJSON = await sendRequest(wsp, request, parachain_api)
	// const metadata = new Metadata(registry, respJSON.value)

	const key = new NodeRSA();
	key.setOptions(
		{
			encryptionScheme: {
				scheme: 'pkcs1_oaep',
				hash: 'sha256',
				label: ''
			}
		}
	);
	key.importKey({
		n: keyJson.n,
		e: keyJson.e
	}, 'components-public');


	// const pubKeyObj = createPublicKey({
	// 	key: {
	// 		"alg": "RSA-OAEP",
	// 		"kty": "RSA",
	// 		"use": "enc",
	// 		n: jose.base64url.encode(keyJson.n),
	// 		e: jose.base64url.encode(Buffer.from('01000001', 'hex')),
	// 	},
	// 	format: "jwk"
	// })



	const alice: KeyringPair = keyring.addFromUri('//Alice', { name: 'Alice' })
	const bob = keyring.addFromUri('//Bob', { name: 'Bob' })

	//could
	const mrenclave = 'BVRh9Q2S7SB1Gz52UcCE4266nNNagEXkDytdfJzsqjmf'
	const shard = '0x9bdd0d29ffd9703c8321c53bfbbc5707fe42d17a1181861f64d00da911ce9286'
	const call = await createTransferTrustedCall(parachain_api, alice, bob.address, mrenclave, shard, toBalance(10))
	//const cyphertext = publicEncrypt(pubKeyObj, call)
	console.log("call: \n" + call);
	const cyphertext = key.encrypt(u8aToBuffer(call))
	console.log("call encrypted: \n" + cyphertext);
	const cypherArray = bufferToU8a(cyphertext);
	console.log("call encrypted: \n" + cypherArray);
	const cyphertext_vec = parachain_api.createType('Vec<u8>', compactAddLength(cypherArray));
	console.log("call encrypted: \n" + cyphertext_vec);
	// const request2 = {jsonrpc: "2.0", method: "test_encrypt", params: Array.prototype.slice.call(cyphertext), id: 1};



	// const encryptResp = await sendRequest(wsp, {
	// 	jsonrpc: "2.0",
	// 	method: "test_encrypt",
	// 	params: Array.from(call),
	// 	id: 1
	// }, parachain_api)
	// console.log(`0x${cyphertext.toString('hex')}`)
	// await parachain_api.tx.teerex.callWorker({
	// 	shard: shard,
	// 	cyphertext: `0x${cyphertext.toString('hex')}`
	// }).signAndSend(alice)

	await parachain_api.tx.teerex.callWorker({
		shard: shard,
		cyphertext: cyphertext_vec
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
