//! End-to-end integration tests for the Quartz handshake protocol.

use cosmwasm_std::{Empty, HexBinary};
use cw_multi_test::{App, AppBuilder, ContractWrapper, Executor};
use sha2::{Digest, Sha256};

use crate::zk_mock::ZkMockStargate;

// ============================================================
// Minimal Quartz app contract (inline, uses mock-sgx attestation)
// ============================================================

mod test_contract {
    use cosmwasm_schema::cw_serde;
    use cosmwasm_std::{
        to_json_binary, Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdResult,
    };
    use quartz_contract_core::{
        handler::RawHandler,
        msg::execute::attested::RawMockAttestation,
        prelude::*,
        state::SESSION,
    };

    type RA = RawMockAttestation;

    #[cw_serde]
    pub struct InstantiateMsg {
        pub quartz: QuartzInstantiateMsg<RA>,
    }

    #[cw_serde]
    pub enum ExecuteMsg {
        Quartz(QuartzExecuteMsg<RA>),
    }

    #[cw_serde]
    pub enum QueryMsg {
        Session {},
    }

    #[cw_serde]
    pub struct SessionResponse {
        pub nonce: HexBinary,
        pub pub_key: Option<HexBinary>,
    }

    pub fn instantiate(
        mut deps: DepsMut,
        env: Env,
        info: MessageInfo,
        msg: InstantiateMsg,
    ) -> Result<Response, quartz_contract_core::error::Error> {
        msg.quartz.handle_raw(deps.branch(), &env, &info)?;
        Ok(Response::new().add_attribute("action", "instantiate"))
    }

    pub fn execute(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        msg: ExecuteMsg,
    ) -> Result<Response, quartz_contract_core::error::Error> {
        match msg {
            ExecuteMsg::Quartz(msg) => msg.handle_raw(deps, &env, &info),
        }
    }

    pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
        match msg {
            QueryMsg::Session {} => {
                let session = SESSION.may_load(deps.storage)?;
                match session {
                    Some(s) => to_json_binary(&SessionResponse {
                        nonce: HexBinary::from(s.nonce().to_vec()),
                        pub_key: s.pub_key(),
                    }),
                    None => to_json_binary(&SessionResponse {
                        nonce: HexBinary::from(vec![0u8; 32]),
                        pub_key: None,
                    }),
                }
            }
        }
    }
}

// ============================================================
// Test helpers
// ============================================================

type TestApp = App<
    cw_multi_test::BankKeeper,
    cosmwasm_std::testing::MockApi,
    cosmwasm_std::testing::MockStorage,
    cw_multi_test::FailingModule<Empty, Empty, Empty>,
    cw_multi_test::WasmKeeper<Empty, Empty>,
    cw_multi_test::StakeKeeper,
    cw_multi_test::DistributionKeeper,
    cw_multi_test::IbcFailingModule,
    cw_multi_test::GovFailingModule,
    ZkMockStargate,
>;

fn setup_app() -> TestApp {
    AppBuilder::new_custom()
        .with_stargate(ZkMockStargate::accepting())
        .build(|_router, _api, _storage| {})
}

/// Build a Config and RawConfig using actual types.
fn build_config() -> quartz_contract_core::state::Config {
    use quartz_contract_core::state::{Config, LightClientOpts};

    let lco = LightClientOpts::new(
        "testing".to_string(),
        1u64,
        [0u8; 32],
        (2u64, 3u64),
        1209600,
        300,
        600,
    )
    .unwrap();

    Config::new([0u8; 32], lco, None)
}

/// Compute mock attestation user_data by going through the actual
/// CoreInstantiate type, exactly matching the contract's HasUserData impl.
fn mock_instantiate_user_data() -> HexBinary {
    use quartz_contract_core::msg::{
        execute::attested::HasUserData,
        instantiate::CoreInstantiate,
    };

    let config = build_config();
    let core_instantiate = CoreInstantiate::new(config);
    core_instantiate.user_data().into()
}


/// Build the full instantiate msg with mock attestation.
fn build_instantiate_msg() -> serde_json::Value {
    let config = build_config();
    let raw_config: quartz_contract_core::state::RawConfig = config.into();
    let raw_config_value = serde_json::to_value(&raw_config).unwrap();
    let raw_core_instantiate = serde_json::json!({ "config": raw_config_value });
    let user_data = mock_instantiate_user_data();

    serde_json::json!({
        "quartz": {
            "msg": raw_core_instantiate,
            "attestation": user_data,
        }
    })
}

/// Build a SessionCreate execute msg with mock attestation.
fn build_session_create_msg(nonce: [u8; 32], contract_addr: &str) -> serde_json::Value {
    use quartz_contract_core::msg::{
        execute::attested::HasUserData,
        execute::session_create::SessionCreate,
    };

    let sc = SessionCreate::new(nonce, contract_addr.to_string());
    let user_data: HexBinary = sc.user_data().into();

    // Build the raw JSON matching RawSessionCreate field order
    let raw_sc = serde_json::json!({
        "nonce": HexBinary::from(nonce.to_vec()),
        "contract": contract_addr,
    });

    serde_json::json!({
        "quartz": {
            "session_create": {
                "msg": raw_sc,
                "attestation": user_data,
            }
        }
    })
}

/// Build a SessionSetPubKey execute msg with mock attestation.
fn build_session_set_pubkey_msg(nonce: [u8; 32], pub_key: Vec<u8>) -> serde_json::Value {
    use quartz_contract_core::msg::{
        execute::attested::HasUserData,
        execute::session_set_pub_key::SessionSetPubKey,
    };

    let spk = SessionSetPubKey::new(nonce, pub_key.clone());
    let user_data: HexBinary = spk.user_data().into();

    let raw_spk = serde_json::json!({
        "nonce": HexBinary::from(nonce.to_vec()),
        "pub_key": HexBinary::from(pub_key),
    });

    serde_json::json!({
        "quartz": {
            "session_set_pub_key": {
                "msg": raw_spk,
                "attestation": user_data,
            }
        }
    })
}

// ============================================================
// Tests
// ============================================================

#[test]
fn test_handshake_full_cycle() {
    let mut app = setup_app();
    let admin = app.api().addr_make("admin");

    let code = ContractWrapper::new(
        test_contract::execute,
        test_contract::instantiate,
        test_contract::query,
    );
    let code_id = app.store_code(Box::new(code));

    // Phase 1: Instantiate
    let init_msg = build_instantiate_msg();
    let contract_addr = app
        .instantiate_contract(code_id, admin.clone(), &init_msg, &[], "quartz-test", None)
        .unwrap();

    // Phase 2: SessionCreate
    let nonce = [42u8; 32];
    let sc_msg = build_session_create_msg(nonce, &contract_addr.to_string());
    app.execute_contract(admin.clone(), contract_addr.clone(), &sc_msg, &[])
        .unwrap();

    // Verify: session created, no pubkey yet
    let session: test_contract::SessionResponse = app
        .wrap()
        .query_wasm_smart(&contract_addr, &test_contract::QueryMsg::Session {})
        .unwrap();
    assert_eq!(session.nonce, HexBinary::from(nonce.to_vec()));
    assert!(session.pub_key.is_none());

    // Phase 3: SessionSetPubKey
    let pub_key = vec![0x04; 33];
    let spk_msg = build_session_set_pubkey_msg(nonce, pub_key.clone());
    app.execute_contract(admin.clone(), contract_addr.clone(), &spk_msg, &[])
        .unwrap();

    // Verify: session complete with pubkey
    let session: test_contract::SessionResponse = app
        .wrap()
        .query_wasm_smart(&contract_addr, &test_contract::QueryMsg::Session {})
        .unwrap();
    assert_eq!(session.nonce, HexBinary::from(nonce.to_vec()));
    assert_eq!(session.pub_key, Some(HexBinary::from(pub_key)));
}

#[test]
fn test_session_create_wrong_contract_addr() {
    let mut app = setup_app();
    let admin = app.api().addr_make("admin");

    let code = ContractWrapper::new(
        test_contract::execute,
        test_contract::instantiate,
        test_contract::query,
    );
    let code_id = app.store_code(Box::new(code));

    let contract_addr = app
        .instantiate_contract(
            code_id,
            admin.clone(),
            &build_instantiate_msg(),
            &[],
            "quartz-test",
            None,
        )
        .unwrap();

    // SessionCreate with valid but wrong contract address
    let wrong_addr = app.api().addr_make("wrong_contract");
    let sc_msg = build_session_create_msg([1u8; 32], wrong_addr.as_str());
    let err = app
        .execute_contract(admin, contract_addr, &sc_msg, &[])
        .unwrap_err();

    let err_str = err.to_string();
    assert!(
        err_str.contains("contract address mismatch") || err_str.contains("ContractAddrMismatch"),
        "Expected contract address error, got: {}",
        err_str
    );
}

#[test]
fn test_session_set_pubkey_wrong_nonce() {
    let mut app = setup_app();
    let admin = app.api().addr_make("admin");

    let code = ContractWrapper::new(
        test_contract::execute,
        test_contract::instantiate,
        test_contract::query,
    );
    let code_id = app.store_code(Box::new(code));

    let contract_addr = app
        .instantiate_contract(
            code_id,
            admin.clone(),
            &build_instantiate_msg(),
            &[],
            "quartz-test",
            None,
        )
        .unwrap();

    // SessionCreate with correct nonce
    let nonce = [42u8; 32];
    let sc_msg = build_session_create_msg(nonce, &contract_addr.to_string());
    app.execute_contract(admin.clone(), contract_addr.clone(), &sc_msg, &[])
        .unwrap();

    // SessionSetPubKey with WRONG nonce
    let wrong_nonce = [99u8; 32];
    let spk_msg = build_session_set_pubkey_msg(wrong_nonce, vec![0x04; 33]);
    let err = app
        .execute_contract(admin, contract_addr, &spk_msg, &[])
        .unwrap_err();

    assert!(err.to_string().contains("invalid session nonce"));
}

#[test]
fn test_double_set_pubkey_rejected() {
    let mut app = setup_app();
    let admin = app.api().addr_make("admin");

    let code = ContractWrapper::new(
        test_contract::execute,
        test_contract::instantiate,
        test_contract::query,
    );
    let code_id = app.store_code(Box::new(code));

    let contract_addr = app
        .instantiate_contract(
            code_id,
            admin.clone(),
            &build_instantiate_msg(),
            &[],
            "quartz-test",
            None,
        )
        .unwrap();

    let nonce = [42u8; 32];
    let sc_msg = build_session_create_msg(nonce, &contract_addr.to_string());
    app.execute_contract(admin.clone(), contract_addr.clone(), &sc_msg, &[])
        .unwrap();

    // First set pubkey succeeds
    let spk_msg = build_session_set_pubkey_msg(nonce, vec![0x04; 33]);
    app.execute_contract(admin.clone(), contract_addr.clone(), &spk_msg, &[])
        .unwrap();

    // Second set pubkey with same nonce should fail
    let spk_msg2 = build_session_set_pubkey_msg(nonce, vec![0x05; 33]);
    let err = app
        .execute_contract(admin, contract_addr, &spk_msg2, &[])
        .unwrap_err();

    assert!(err.to_string().contains("invalid session nonce"));
}
