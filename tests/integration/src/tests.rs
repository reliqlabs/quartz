//! End-to-end integration tests for the Quartz handshake protocol.
//!
//! Tests use DstackAttestation (non-mock) with the ZkMockStargate handler.
//! When zkdcap_vkey is None, the handler skips ZK verification.
//! When zkdcap_vkey is set, the handler queries the ZK mock which validates
//! proof structure.

use cosmwasm_std::{Empty, HexBinary};
use cw_multi_test::{App, AppBuilder, ContractWrapper, Executor};

use crate::fixtures::ZkdcapFixture;
use crate::zk_mock::ZkMockStargate;

// ============================================================
// Minimal Quartz app contract using DstackAttestation
// ============================================================

mod test_contract {
    use cosmwasm_schema::cw_serde;
    use cosmwasm_std::{
        to_json_binary, Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response, StdResult,
    };
    use quartz_contract_core::{
        handler::RawHandler,
        msg::execute::attested::RawDstackAttestation,
        prelude::*,
        state::SESSION,
    };

    type RA = RawDstackAttestation;

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

fn setup_app(mock: ZkMockStargate) -> TestApp {
    AppBuilder::new_custom()
        .with_stargate(mock)
        .build(|_router, _api, _storage| {})
}

/// Build Config using actual types for correct serialization.
fn build_config(
    mr_enclave: [u8; 32],
    zkdcap_vkey: Option<String>,
) -> quartz_contract_core::state::Config {
    use quartz_contract_core::state::{Config, LightClientOpts};

    let lco = LightClientOpts::new(
        "testing".to_string(), 1u64, [0u8; 32], (2u64, 3u64), 1209600, 300, 600,
    ).unwrap();

    Config::new(mr_enclave, lco, zkdcap_vkey)
}

/// Build a DstackAttestation JSON value with the given fields.
fn build_dstack_attestation(
    quote: &[u8],
    user_data: [u8; 64],
    compose_hash: [u8; 32],
    proof: &[u8],
    public_inputs: &[String],
    journal: &[u8],
) -> serde_json::Value {
    serde_json::json!({
        "quote": HexBinary::from(quote.to_vec()),
        "event_log": null,
        "user_data": HexBinary::from(user_data.to_vec()),
        "compose_hash": HexBinary::from(compose_hash.to_vec()),
        "zkdcap_proof": HexBinary::from(proof.to_vec()),
        "zkdcap_public_inputs": public_inputs,
        "zkdcap_journal": HexBinary::from(journal.to_vec()),
    })
}

/// Compute user_data via CoreInstantiate's HasUserData impl.
fn instantiate_user_data(config: &quartz_contract_core::state::Config) -> [u8; 64] {
    use quartz_contract_core::msg::{
        execute::attested::HasUserData,
        instantiate::CoreInstantiate,
    };
    CoreInstantiate::new(config.clone()).user_data()
}

/// Compute user_data via SessionCreate's HasUserData impl.
fn session_create_user_data(nonce: [u8; 32], contract: &str) -> [u8; 64] {
    use quartz_contract_core::msg::{
        execute::attested::HasUserData,
        execute::session_create::SessionCreate,
    };
    SessionCreate::new(nonce, contract.to_string()).user_data()
}

/// Compute user_data via SessionSetPubKey's HasUserData impl.
fn session_set_pubkey_user_data(nonce: [u8; 32], pub_key: Vec<u8>) -> [u8; 64] {
    use quartz_contract_core::msg::{
        execute::attested::HasUserData,
        execute::session_set_pub_key::SessionSetPubKey,
    };
    SessionSetPubKey::new(nonce, pub_key).user_data()
}

// ============================================================
// Tests: Handshake (no ZK verification, zkdcap_vkey = None)
// ============================================================

#[test]
fn test_handshake_full_cycle() {
    let mut app = setup_app(ZkMockStargate::accepting());
    let admin = app.api().addr_make("admin");
    let code = ContractWrapper::new(
        test_contract::execute, test_contract::instantiate, test_contract::query,
    );
    let code_id = app.store_code(Box::new(code));

    let mr_enclave = [0u8; 32]; // DstackAttestation.compose_hash must match
    let config = build_config(mr_enclave, None);
    let raw_config: quartz_contract_core::state::RawConfig = config.clone().into();

    let user_data = instantiate_user_data(&config);
    let attestation = build_dstack_attestation(
        &[0xDE, 0xAD], user_data, mr_enclave, &[], &[], &[],
    );

    let raw_core = serde_json::json!({
        "config": serde_json::to_value(&raw_config).unwrap()
    });
    let init_msg = serde_json::json!({
        "quartz": { "msg": raw_core, "attestation": attestation }
    });

    let contract_addr = app
        .instantiate_contract(code_id, admin.clone(), &init_msg, &[], "quartz-test", None)
        .unwrap();

    // Phase 2: SessionCreate
    let nonce = [42u8; 32];
    let sc_ud = session_create_user_data(nonce, &contract_addr.to_string());
    let sc_attest = build_dstack_attestation(
        &[0xDE, 0xAD], sc_ud, mr_enclave, &[], &[], &[],
    );
    let sc_msg = serde_json::json!({
        "quartz": {
            "session_create": {
                "msg": {
                    "nonce": HexBinary::from(nonce.to_vec()),
                    "contract": contract_addr.to_string(),
                },
                "attestation": sc_attest,
            }
        }
    });
    app.execute_contract(admin.clone(), contract_addr.clone(), &sc_msg, &[]).unwrap();

    let session: test_contract::SessionResponse = app
        .wrap()
        .query_wasm_smart(&contract_addr, &test_contract::QueryMsg::Session {})
        .unwrap();
    assert_eq!(session.nonce, HexBinary::from(nonce.to_vec()));
    assert!(session.pub_key.is_none());

    // Phase 3: SessionSetPubKey
    let pub_key = vec![0x04; 33];
    let spk_ud = session_set_pubkey_user_data(nonce, pub_key.clone());
    let spk_attest = build_dstack_attestation(
        &[0xDE, 0xAD], spk_ud, mr_enclave, &[], &[], &[],
    );
    let spk_msg = serde_json::json!({
        "quartz": {
            "session_set_pub_key": {
                "msg": {
                    "nonce": HexBinary::from(nonce.to_vec()),
                    "pub_key": HexBinary::from(pub_key.clone()),
                },
                "attestation": spk_attest,
            }
        }
    });
    app.execute_contract(admin.clone(), contract_addr.clone(), &spk_msg, &[]).unwrap();

    let session: test_contract::SessionResponse = app
        .wrap()
        .query_wasm_smart(&contract_addr, &test_contract::QueryMsg::Session {})
        .unwrap();
    assert_eq!(session.nonce, HexBinary::from(nonce.to_vec()));
    assert_eq!(session.pub_key, Some(HexBinary::from(pub_key)));
}

#[test]
fn test_session_create_wrong_contract_addr() {
    let mut app = setup_app(ZkMockStargate::accepting());
    let admin = app.api().addr_make("admin");
    let code = ContractWrapper::new(
        test_contract::execute, test_contract::instantiate, test_contract::query,
    );
    let code_id = app.store_code(Box::new(code));

    let mr_enclave = [0u8; 32];
    let config = build_config(mr_enclave, None);
    let raw_config: quartz_contract_core::state::RawConfig = config.clone().into();
    let user_data = instantiate_user_data(&config);
    let attestation = build_dstack_attestation(&[0xDE, 0xAD], user_data, mr_enclave, &[], &[], &[]);
    let raw_core = serde_json::json!({"config": serde_json::to_value(&raw_config).unwrap()});
    let init_msg = serde_json::json!({"quartz": {"msg": raw_core, "attestation": attestation}});

    let contract_addr = app
        .instantiate_contract(code_id, admin.clone(), &init_msg, &[], "quartz-test", None)
        .unwrap();

    let wrong_addr = app.api().addr_make("wrong_contract");
    let sc_ud = session_create_user_data([1u8; 32], wrong_addr.as_str());
    let sc_attest = build_dstack_attestation(&[0xDE, 0xAD], sc_ud, mr_enclave, &[], &[], &[]);
    let sc_msg = serde_json::json!({
        "quartz": {"session_create": {"msg": {"nonce": HexBinary::from(vec![1u8; 32]), "contract": wrong_addr.to_string()}, "attestation": sc_attest}}
    });

    let err = app.execute_contract(admin, contract_addr, &sc_msg, &[]).unwrap_err();
    assert!(err.to_string().contains("contract address mismatch") || err.to_string().contains("ContractAddrMismatch"),
        "Expected contract address error, got: {}", err);
}

#[test]
fn test_session_set_pubkey_wrong_nonce() {
    let mut app = setup_app(ZkMockStargate::accepting());
    let admin = app.api().addr_make("admin");
    let code = ContractWrapper::new(
        test_contract::execute, test_contract::instantiate, test_contract::query,
    );
    let code_id = app.store_code(Box::new(code));

    let mr_enclave = [0u8; 32];
    let config = build_config(mr_enclave, None);
    let raw_config: quartz_contract_core::state::RawConfig = config.clone().into();
    let user_data = instantiate_user_data(&config);
    let attestation = build_dstack_attestation(&[0xDE, 0xAD], user_data, mr_enclave, &[], &[], &[]);
    let raw_core = serde_json::json!({"config": serde_json::to_value(&raw_config).unwrap()});
    let init_msg = serde_json::json!({"quartz": {"msg": raw_core, "attestation": attestation}});

    let contract_addr = app
        .instantiate_contract(code_id, admin.clone(), &init_msg, &[], "quartz-test", None)
        .unwrap();

    let nonce = [42u8; 32];
    let sc_ud = session_create_user_data(nonce, &contract_addr.to_string());
    let sc_attest = build_dstack_attestation(&[0xDE, 0xAD], sc_ud, mr_enclave, &[], &[], &[]);
    let sc_msg = serde_json::json!({
        "quartz": {"session_create": {"msg": {"nonce": HexBinary::from(nonce.to_vec()), "contract": contract_addr.to_string()}, "attestation": sc_attest}}
    });
    app.execute_contract(admin.clone(), contract_addr.clone(), &sc_msg, &[]).unwrap();

    let wrong_nonce = [99u8; 32];
    let spk_ud = session_set_pubkey_user_data(wrong_nonce, vec![0x04; 33]);
    let spk_attest = build_dstack_attestation(&[0xDE, 0xAD], spk_ud, mr_enclave, &[], &[], &[]);
    let spk_msg = serde_json::json!({
        "quartz": {"session_set_pub_key": {"msg": {"nonce": HexBinary::from(wrong_nonce.to_vec()), "pub_key": HexBinary::from(vec![0x04u8; 33])}, "attestation": spk_attest}}
    });

    let err = app.execute_contract(admin, contract_addr, &spk_msg, &[]).unwrap_err();
    assert!(err.to_string().contains("invalid session nonce"));
}

// ============================================================
// Tests: Proof verification (zkdcap_vkey set, ZK mock validates)
// ============================================================

#[test]
fn test_handshake_with_zkdcap_proof_verification() {
    let mut app = setup_app(ZkMockStargate::validating());
    let admin = app.api().addr_make("admin");
    let code = ContractWrapper::new(
        test_contract::execute, test_contract::instantiate, test_contract::query,
    );
    let code_id = app.store_code(Box::new(code));

    let fixture = ZkdcapFixture::generate();
    let mr_enclave = fixture.compose_hash;

    // Config with zkdcap_vkey set — handler will query ZK module
    let config = build_config(mr_enclave, Some("zkdcap-test".to_string()));
    let raw_config: quartz_contract_core::state::RawConfig = config.clone().into();

    let user_data = instantiate_user_data(&config);
    let attestation = build_dstack_attestation(
        &fixture.quote_bytes,
        user_data,
        mr_enclave,
        &fixture.proof_bytes,
        &fixture.public_inputs,
        &fixture.journal_bytes,
    );

    let raw_core = serde_json::json!({
        "config": serde_json::to_value(&raw_config).unwrap()
    });
    let init_msg = serde_json::json!({
        "quartz": { "msg": raw_core, "attestation": attestation }
    });

    // Instantiate — DstackAttestation handler queries ZK mock with real proof structure
    let contract_addr = app
        .instantiate_contract(code_id, admin.clone(), &init_msg, &[], "quartz-zkdcap", None)
        .unwrap();

    // Session handshake with proof data
    let nonce = [42u8; 32];
    let sc_ud = session_create_user_data(nonce, &contract_addr.to_string());
    let sc_attest = build_dstack_attestation(
        &fixture.quote_bytes, sc_ud, mr_enclave,
        &fixture.proof_bytes, &fixture.public_inputs, &fixture.journal_bytes,
    );
    let sc_msg = serde_json::json!({
        "quartz": {"session_create": {"msg": {"nonce": HexBinary::from(nonce.to_vec()), "contract": contract_addr.to_string()}, "attestation": sc_attest}}
    });
    app.execute_contract(admin.clone(), contract_addr.clone(), &sc_msg, &[]).unwrap();

    let pub_key = vec![0x04; 33];
    let spk_ud = session_set_pubkey_user_data(nonce, pub_key.clone());
    let spk_attest = build_dstack_attestation(
        &fixture.quote_bytes, spk_ud, mr_enclave,
        &fixture.proof_bytes, &fixture.public_inputs, &fixture.journal_bytes,
    );
    let spk_msg = serde_json::json!({
        "quartz": {"session_set_pub_key": {"msg": {"nonce": HexBinary::from(nonce.to_vec()), "pub_key": HexBinary::from(pub_key.clone())}, "attestation": spk_attest}}
    });
    app.execute_contract(admin.clone(), contract_addr.clone(), &spk_msg, &[]).unwrap();

    // Verify handshake completed
    let session: test_contract::SessionResponse = app
        .wrap()
        .query_wasm_smart(&contract_addr, &test_contract::QueryMsg::Session {})
        .unwrap();
    assert_eq!(session.pub_key, Some(HexBinary::from(pub_key)));
}

#[test]
fn test_zkdcap_invalid_proof_rejected() {
    let mut app = setup_app(ZkMockStargate::validating());
    let admin = app.api().addr_make("admin");
    let code = ContractWrapper::new(
        test_contract::execute, test_contract::instantiate, test_contract::query,
    );
    let code_id = app.store_code(Box::new(code));

    let mr_enclave = [0u8; 32];
    let config = build_config(mr_enclave, Some("zkdcap-test".to_string()));
    let raw_config: quartz_contract_core::state::RawConfig = config.clone().into();
    let user_data = instantiate_user_data(&config);

    // Invalid proof — not valid JSON, not SnarkJS format
    let bad_proof = b"not a valid proof".to_vec();
    let attestation = build_dstack_attestation(
        &[0xDE, 0xAD], user_data, mr_enclave,
        &bad_proof, &["123".to_string()], &[],
    );

    let raw_core = serde_json::json!({"config": serde_json::to_value(&raw_config).unwrap()});
    let init_msg = serde_json::json!({"quartz": {"msg": raw_core, "attestation": attestation}});

    let err = app
        .instantiate_contract(code_id, admin, &init_msg, &[], "quartz-bad", None)
        .unwrap_err();

    assert!(err.to_string().contains("zkdcap verification failed") || err.to_string().contains("not valid JSON"),
        "Expected ZK verification error, got: {}", err);
}

// ============================================================
// Tests: gnark native ZK mock (ProofVerifyGnark endpoint)
// ============================================================

#[test]
fn test_gnark_mock_accepts_valid_proof() {
    use crate::zk_mock::{QueryVerifyGnarkRequest, ProofVerifyGnarkResponse};
    use crate::fixtures::GnarkFixture;
    use prost::Message;

    let mock = crate::zk_mock::ZkMockStargate::validating();
    let fixture = GnarkFixture::generate();

    let req = QueryVerifyGnarkRequest {
        proof: fixture.proof_bytes,
        public_inputs: fixture.public_inputs_bytes,
        vkey_name: "zkdcap-gnark".to_string(),
        vkey_id: 0,
    };
    let mut req_bytes = Vec::new();
    req.encode(&mut req_bytes).unwrap();

    let resp_bytes = mock.dispatch(
        "/xion.zk.v1.Query/ProofVerifyGnark",
        &req_bytes,
    ).unwrap();

    let resp = ProofVerifyGnarkResponse::decode(resp_bytes.as_slice()).unwrap();
    assert!(resp.verified, "valid gnark proof should verify");
}

#[test]
fn test_gnark_mock_rejects_empty_proof() {
    use crate::zk_mock::{QueryVerifyGnarkRequest, ProofVerifyGnarkResponse};
    use prost::Message;

    let mock = crate::zk_mock::ZkMockStargate::validating();

    let req = QueryVerifyGnarkRequest {
        proof: vec![],
        public_inputs: vec![0u8; 64],
        vkey_name: "zkdcap-gnark".to_string(),
        vkey_id: 0,
    };
    let mut req_bytes = Vec::new();
    req.encode(&mut req_bytes).unwrap();

    let resp_bytes = mock.dispatch(
        "/xion.zk.v1.Query/ProofVerifyGnark",
        &req_bytes,
    ).unwrap();

    let resp = ProofVerifyGnarkResponse::decode(resp_bytes.as_slice()).unwrap();
    assert!(!resp.verified, "empty proof should not verify");
}

#[test]
fn test_gnark_mock_rejects_bad_public_inputs() {
    use crate::zk_mock::{QueryVerifyGnarkRequest, ProofVerifyGnarkResponse};
    use prost::Message;

    let mock = crate::zk_mock::ZkMockStargate::validating();

    let req = QueryVerifyGnarkRequest {
        proof: vec![0x42; 384], // valid size
        public_inputs: vec![0u8; 33], // not a multiple of 32
        vkey_name: "zkdcap-gnark".to_string(),
        vkey_id: 0,
    };
    let mut req_bytes = Vec::new();
    req.encode(&mut req_bytes).unwrap();

    let resp_bytes = mock.dispatch(
        "/xion.zk.v1.Query/ProofVerifyGnark",
        &req_bytes,
    ).unwrap();

    let resp = ProofVerifyGnarkResponse::decode(resp_bytes.as_slice()).unwrap();
    assert!(!resp.verified, "misaligned public inputs should not verify");
}

#[test]
fn test_gnark_mock_rejects_short_proof() {
    use crate::zk_mock::{QueryVerifyGnarkRequest, ProofVerifyGnarkResponse};
    use prost::Message;

    let mock = crate::zk_mock::ZkMockStargate::validating();

    let req = QueryVerifyGnarkRequest {
        proof: vec![0x42; 50], // too short for BN254 Groth16
        public_inputs: vec![0u8; 64],
        vkey_name: "zkdcap-gnark".to_string(),
        vkey_id: 0,
    };
    let mut req_bytes = Vec::new();
    req.encode(&mut req_bytes).unwrap();

    let resp_bytes = mock.dispatch(
        "/xion.zk.v1.Query/ProofVerifyGnark",
        &req_bytes,
    ).unwrap();

    let resp = ProofVerifyGnarkResponse::decode(resp_bytes.as_slice()).unwrap();
    assert!(!resp.verified, "short proof should not verify");
}
