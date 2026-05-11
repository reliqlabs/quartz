//! Model-based testing: replay Quint ITF traces against the real contract.
//!
//! Generates traces from specs/handshake.qnt via `quint run --out-itf`,
//! then replays successful state transitions against the contract in
//! cw-multi-test, verifying the implementation accepts what the spec accepts.
//!
//! Run: `cargo test model_based -- --nocapture`

use cosmwasm_std::{Empty, HexBinary};
use cw_multi_test::{AppBuilder, ContractWrapper, Executor};
use serde_json::Value;

use crate::zk_mock::ZkMockStargate;

// ── Reuse test contract from tests.rs ──────────────────────────────

mod mbt_contract {
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

// ── App type alias ─────────────────────────────────────────────────

type TestApp = cw_multi_test::App<
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

// ── ITF parsing ────────────────────────────────────────────────────

#[allow(dead_code)]
struct ItfState {
    config_set: bool,
    session_tag: String,
    session_nonce: String,
    session_pubkey: String,
    last_result: String,
}

fn parse_state(state: &Value) -> ItfState {
    let c = &state["contract"];
    ItfState {
        config_set: c["config_set"].as_bool().unwrap_or(false),
        session_tag: c["session"]["tag"].as_str().unwrap_or("NoSession").to_string(),
        session_nonce: c["session_nonce"].as_str().unwrap_or("").to_string(),
        session_pubkey: c["session_pubkey"].as_str().unwrap_or("").to_string(),
        last_result: state["last_result"]["tag"].as_str().unwrap_or("").to_string(),
    }
}

// ── Helpers ────────────────────────────────────────────────────────

fn build_config(mr_enclave: [u8; 32]) -> quartz_contract_core::state::Config {
    quartz_contract_core::state::Config::new(
        mr_enclave,
        quartz_contract_core::state::LightClientOpts::new(
            "testing".to_string(), 1, [0u8; 32], (2, 3), 1209600, 300, 600,
        ).unwrap(),
        None,
    )
}

fn instantiate_user_data(config: &quartz_contract_core::state::Config) -> [u8; 64] {
    use quartz_contract_core::msg::execute::attested::HasUserData;
    use quartz_contract_core::msg::instantiate::CoreInstantiate;
    CoreInstantiate::new(config.clone()).user_data()
}

fn session_create_user_data(nonce: [u8; 32], contract: &str) -> [u8; 64] {
    use quartz_contract_core::msg::execute::attested::HasUserData;
    use quartz_contract_core::msg::execute::session_create::SessionCreate;
    SessionCreate::new(nonce, contract.to_string()).user_data()
}

fn session_set_pubkey_user_data(nonce: [u8; 32], pub_key: Vec<u8>) -> [u8; 64] {
    use quartz_contract_core::msg::execute::attested::HasUserData;
    use quartz_contract_core::msg::execute::session_set_pub_key::SessionSetPubKey;
    SessionSetPubKey::new(nonce, pub_key).user_data()
}

fn build_attestation(user_data: [u8; 64], compose_hash: [u8; 32]) -> serde_json::Value {
    serde_json::json!({
        "user_data": HexBinary::from(user_data.to_vec()),
        "compose_hash": HexBinary::from(compose_hash.to_vec()),
        "quote": HexBinary::from(vec![0xDE, 0xAD]),
        "event_log": null,
    })
}

// ── Trace replay ───────────────────────────────────────────────────

/// Replay one ITF trace. For each step where the spec says Ok and the
/// transition is a recognized action, execute against the contract and
/// assert success. Count matches.
fn replay_trace(path: &std::path::Path) -> (usize, usize, usize) {
    let trace: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let states = trace["states"].as_array().unwrap();
    if states.len() < 2 {
        return (0, 0, 0);
    }

    let mr_enclave = [0xAA; 32];
    let nonce = [0x42u8; 32];
    let pub_key = vec![0x04; 33];

    let mut app: TestApp = AppBuilder::new_custom()
        .with_stargate(ZkMockStargate::accepting())
        .build(|_r, _a, _s| {});

    let admin = app.api().addr_make("admin");
    let code = ContractWrapper::new(
        mbt_contract::execute,
        mbt_contract::instantiate,
        mbt_contract::query,
    );
    let code_id = app.store_code(Box::new(code));

    let config = build_config(mr_enclave);
    let raw_config: quartz_contract_core::state::RawConfig = config.clone().into();

    let mut contract_addr: Option<cosmwasm_std::Addr> = None;
    let mut ok_replayed = 0;
    let mut err_observed = 0;
    let mut steps = 0;

    for i in 1..states.len() {
        let prev = parse_state(&states[i - 1]);
        let curr = parse_state(&states[i]);
        steps += 1;

        if curr.last_result != "Ok" {
            err_observed += 1;
            continue;
        }

        // Detect action by state diff
        if !prev.config_set && curr.config_set {
            // Instantiate
            let ud = instantiate_user_data(&config);
            let att = build_attestation(ud, mr_enclave);
            let raw_core = serde_json::json!({"config": serde_json::to_value(&raw_config).unwrap()});
            let msg = serde_json::json!({"quartz": {"msg": raw_core, "attestation": att}});

            let result = app.instantiate_contract(code_id, admin.clone(), &msg, &[], "quartz-mbt", None);
            assert!(result.is_ok(), "Step {i}: spec Ok, contract failed: {:?}", result.err());
            contract_addr = Some(result.unwrap());
            ok_replayed += 1;
        } else if prev.session_tag != "SessionCreated" && curr.session_tag == "SessionCreated" {
            // SessionCreate
            let addr = contract_addr.as_ref().expect("no contract");
            let ud = session_create_user_data(nonce, &addr.to_string());
            let att = build_attestation(ud, mr_enclave);
            let msg = serde_json::json!({
                "quartz": {"session_create": {"msg": {"nonce": HexBinary::from(nonce.to_vec()), "contract": addr.to_string()}, "attestation": att}}
            });
            let result = app.execute_contract(admin.clone(), addr.clone(), &msg, &[]);
            assert!(result.is_ok(), "Step {i}: spec Ok, contract failed: {:?}", result.err());
            ok_replayed += 1;
        } else if prev.session_tag == "SessionCreated" && curr.session_tag == "SessionActive" {
            // SessionSetPubKey
            let addr = contract_addr.as_ref().expect("no contract");
            let ud = session_set_pubkey_user_data(nonce, pub_key.clone());
            let att = build_attestation(ud, mr_enclave);
            let msg = serde_json::json!({
                "quartz": {"session_set_pub_key": {"msg": {"nonce": HexBinary::from(nonce.to_vec()), "pub_key": HexBinary::from(pub_key.clone())}, "attestation": att}}
            });
            let result = app.execute_contract(admin.clone(), addr.clone(), &msg, &[]);
            assert!(result.is_ok(), "Step {i}: spec Ok, contract failed: {:?}", result.err());
            ok_replayed += 1;
        }
    }

    (steps, ok_replayed, err_observed)
}

// ── Test ────────────────────────────────────────────────────────────

#[test]
fn test_model_based_replay() {
    let trace_dir = std::env::temp_dir().join("quartz_mbt");
    std::fs::create_dir_all(&trace_dir).unwrap();

    let spec_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../specs/handshake.qnt");

    assert!(spec_path.exists(), "Spec not found: {}", spec_path.display());

    let trace_pattern = trace_dir.join("trace_{seq}.itf.json");
    let output = std::process::Command::new("quint")
        .args([
            "run",
            spec_path.to_str().unwrap(),
            "--max-steps=15",
            "--n-traces=10",
            "--max-samples=50000",
            &format!("--out-itf={}", trace_pattern.to_str().unwrap()),
        ])
        .output()
        .expect("quint not installed");

    assert!(output.status.success(), "quint run failed: {}", String::from_utf8_lossy(&output.stderr));

    let mut total_traces = 0;
    let mut total_steps = 0;
    let mut total_ok = 0;
    let mut total_err = 0;

    for entry in std::fs::read_dir(&trace_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().map(|e| e == "json").unwrap_or(false) {
            let (steps, ok, err) = replay_trace(&path);
            total_traces += 1;
            total_steps += steps;
            total_ok += ok;
            total_err += err;
        }
    }

    eprintln!(
        "Model-based testing: {} traces, {} steps, {} ok replayed, {} errors observed",
        total_traces, total_steps, total_ok, total_err
    );
    assert!(total_traces > 0, "No traces generated");
    assert!(total_ok > 0, "No successful transitions replayed");

    std::fs::remove_dir_all(&trace_dir).ok();
}
