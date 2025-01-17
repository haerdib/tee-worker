// Copyright 2020-2022 Litentry Technologies GmbH.
// This file is part of Litentry.
//
// Litentry is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Litentry is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Litentry.  If not, see <https://www.gnu.org/licenses/>.

use crate::{
	helpers::get_parentchain_number, stf_sgx_primitives::types::*, AccountId, StfError, StfResult,
};
#[cfg(all(not(feature = "std"), feature = "sgx"))]
extern crate sgx_tstd as std;
use codec::Encode;
use ita_sgx_runtime::Runtime;
use litentry_primitives::{
	eth::{EthAddress, EthSignature},
	LinkingAccountIndex, UserShieldingKeyType,
};
use log::*;

use pallet_sgx_account_linker::{MultiSignature, NetworkType};

use std::format;
use support::traits::UnfilteredDispatchable;

use itc_https_client_daemon::daemon_sender::SendHttpsRequest;
use itp_utils::stringify::account_id_to_string;

impl Stf {
	pub fn set_shielding_key(who: AccountId, key: UserShieldingKeyType) -> StfResult<()> {
		debug!("who.str = {:?}, key = {:?}", account_id_to_string(&who), key.clone());
		ita_sgx_runtime::IdentityManagementCall::<Runtime>::set_user_shielding_key { who, key }
			.dispatch_bypass_filter(ita_sgx_runtime::Origin::root())
			.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;
		Ok(())
	}

	pub fn link_eth(
		account: AccountId,
		index: LinkingAccountIndex,
		eth_address: EthAddress,
		block_number: BlockNumber,
		signature: EthSignature,
	) -> StfResult<()> {
		debug!(
			"link_eth({:x?}, {:?}, {:?}, {:?}, {:?})",
			account.encode(),
			index,
			eth_address,
			block_number,
			signature
		);

		// set origin from enclave to original user (otherwise pallet throws BadOrigin error)
		let origin = ita_sgx_runtime::Origin::signed(account.clone());

		match get_parentchain_number() {
			Some(number) => {
				ita_sgx_runtime::SgxAccountLinkerCall::<Runtime>::link_eth {
					account,
					index,
					addr_expected: eth_address,
					layer_one_block_number: number,
					expiring_block_number: block_number,
					sig: signature,
				}
				.dispatch_bypass_filter(origin)
				.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;
				Ok(())
			},
			None => {
				error!("link_eth blocknumber l1 unavailable");
				Err(StfError::LayerOneNumberUnavailable)
			},
		}
	}

	pub fn link_sub(
		account: AccountId,
		index: LinkingAccountIndex,
		network_type: NetworkType,
		linked_account: AccountId,
		block_number: BlockNumber,
		signature: MultiSignature,
	) -> StfResult<()> {
		debug!(
			"link_sub({:x?}, {:?}, {:?}, {:x?}, {:?}), {:?})",
			account.encode(),
			index,
			network_type,
			linked_account.encode(),
			block_number,
			signature
		);

		// set origin from enclave to original user (otherwise pallet throws BadOrigin error)
		let origin = ita_sgx_runtime::Origin::signed(account.clone());

		match get_parentchain_number() {
			Some(number) => {
				ita_sgx_runtime::SgxAccountLinkerCall::<Runtime>::link_sub {
					account,
					index,
					network_type,
					linked_account,
					layer_one_block_number: number,
					expiring_block_number: block_number,
					sig: signature,
				}
				.dispatch_bypass_filter(origin)
				.map_err(|e| StfError::Dispatch(format!("{:?}", e.error)))?;
				Ok(())
			},
			None => {
				error!("link_sub blocknumber l1 unavailable");
				Err(StfError::LayerOneNumberUnavailable)
			},
		}
	}

	pub fn query_credit(account_id: AccountId) -> StfResult<()> {
		info!("query_credit({:x?})", account_id.encode(),);

		let request_str = format!("{}", "https://httpbin.org/anything");
		let request = itc_https_client_daemon::Request { account_id, request_str };
		let sender = itc_https_client_daemon::daemon_sender::HttpRequestSender::new();
		let result = sender.send_https_request(request);
		info!("send https request, get result as {:?}", result);

		Ok(())
	}
}
