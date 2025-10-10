use std::{path::PathBuf, str::FromStr};
use anyhow::anyhow;
use spaces_client::{
    rpc::{
        RpcClient, RpcWalletRequest,
        RpcWalletTxBuilder,
    },
    wallets::{AddressKind, WalletResponse},
};
use spaces_client::rpc::{CommitParams, CreatePtrParams, TransferPtrParams, TransferSpacesParams};
use spaces_client::store::Sha256;
use spaces_protocol::{bitcoin, bitcoin::{FeeRate}};
use spaces_protocol::bitcoin::hashes::{sha256, Hash};
use spaces_ptr::sptr::Sptr;
use spaces_ptr::transcript_hash;
use spaces_testutil::TestRig;
use spaces_wallet::{export::WalletExport};
use spaces_wallet::address::SpaceAddress;

const ALICE: &str = "wallet_99";
const BOB: &str = "wallet_98";
const EVE: &str = "wallet_93";

async fn it_should_create_sptrs(rig: &TestRig) -> anyhow::Result<()> {
    rig.wait_until_wallet_synced(ALICE).await?;

    // 1) Create ptr bound to addr0 (spk0)
    let addr0 = rig.spaced.client.wallet_get_new_address(ALICE, AddressKind::Coin).await?;
    let addr0_spk = bitcoin::address::Address::from_str(&addr0)
        .expect("valid").assume_checked()
        .script_pubkey();
    let addr0_spk_string = hex::encode(addr0_spk.as_bytes());

    let create0 = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::CreatePtr(CreatePtrParams { spk: addr0_spk_string.clone() })],
        false,
    ).await.expect("CreatePtr addr0");
    assert!(wallet_res_err(&create0).is_ok(), "CreatePtr(addr0) must not error");

    rig.mine_blocks(1, None).await?;
    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(ALICE).await?;

    let spk0 = bitcoin::address::Address::from_str(&addr0)
        .expect("valid addr0")
        .assume_checked()
        .script_pubkey();
    let sptr0 = Sptr::from_spk::<Sha256>(spk0.clone());

    let ptr0 = rig.spaced.client.get_ptr(sptr0).await?
        .expect("ptr must exist after first CreatePtr");
    let bound_spk_before = ptr0.ptrout.script_pubkey.clone();

    // 2) Transfer ptr to addr1 (binding should change to spk1)
    let addr1 = rig.spaced.client.wallet_get_new_address(BOB, AddressKind::Space).await?;
    let xfer = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::TransferPtr(TransferPtrParams {
            ptrs: vec![sptr0],
            to: addr1.clone(),
        })],
        false,
    ).await.expect("TransferPtr to addr1");
    assert!(wallet_res_err(&xfer).is_ok(), "TransferPtr must not error");

    rig.mine_blocks(1, None).await?;
    rig.wait_until_wallet_synced(ALICE).await?;
    rig.wait_until_wallet_synced(BOB).await?;
    rig.wait_until_synced().await?;


    let spk1 = SpaceAddress::from_str(&addr1)
        .expect("valid addr1")
        .script_pubkey();

    let ptr_after_xfer = rig.spaced.client.get_ptr(sptr0).await?
        .expect("ptr must still resolve after transfer");
    let bound_spk_after = ptr_after_xfer.ptrout.script_pubkey.clone();

    assert_ne!(bound_spk_before, bound_spk_after, "binding must change after transfer");
    assert_eq!(bound_spk_after, spk1, "binding must equal new destination spk");

    // 3) Duplicate CreatePtr on ORIGINAL addr0 → tx is produced but MUST NOT overwrite binding
    let dup = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::CreatePtr(CreatePtrParams { spk: addr0_spk_string })],
        false,
    ).await.expect("duplicate CreatePtr(addr0)");
    assert!(wallet_res_err(&dup).is_ok(), "duplicate CreatePtr should not error");
    assert!(!dup.result.is_empty(), "protocol still emits a tx for duplicate CreatePtr");

    rig.mine_blocks(1, None).await?;
    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(ALICE).await?;

    let ptr_after_dup = rig.spaced.client.get_ptr(sptr0).await?
        .expect("ptr must still resolve after duplicate");
    let bound_spk_final = ptr_after_dup.ptrout.script_pubkey.clone();

    assert_eq!(
        bound_spk_final, spk1,
        "duplicate CreatePtr(addr0) must be ignored: binding stays at spk1"
    );
    assert_ne!(
        bound_spk_final, spk0,
        "binding must not be overwritten back to original spk0"
    );

    Ok(())
}

async fn it_should_operate_space(rig: &TestRig) -> anyhow::Result<()> {
    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(ALICE).await?;

    // Pick any space Alice already OWNS.
    let alice_spaces = rig.spaced.client.wallet_list_spaces(ALICE).await?;
    let owned = alice_spaces
        .owned
        .first()
        .cloned()
        .expect("Alice should own at least one space for this test");
    let space_name = owned
        .spaceout
        .space
        .as_ref()
        .expect("space must exist")
        .name
        .to_string();

    // Fetch full space and capture its current scriptPubKey (will be used for SPTR + address).
    let full_before = rig
        .spaced
        .client
        .get_space(&space_name)
        .await?
        .expect("space must exist");

    let current_spk = full_before.spaceout.script_pubkey.clone();
    let res = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Transfer(TransferSpacesParams {
            spaces: vec![space_name.clone()],
            to: None,
        })],
        false,
    )
        .await
        .expect("send transfer-to-same-address (renewal)");

    assert!(wallet_res_err(&res).is_ok(), "tx should not error");

    // Confirm renewal.
    rig.mine_blocks(1, None).await?;
    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(ALICE).await?;

    let full_after = rig
        .spaced
        .client
        .get_space(&space_name)
        .await?
        .expect("space must still exist");
    let spk_after = full_after.spaceout.script_pubkey.clone();

    // Address/script must be identical after renewal.
    assert_eq!(current_spk, spk_after, "space spk must remain the same after renewal");

    // --- Create/bind an SPTR using the SAME scriptPubKey as the space ---
    let create_ptr_res = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::CreatePtr(CreatePtrParams {
            spk: hex::encode(current_spk.as_bytes()),
        })],
        false,
    )
        .await
        .expect("send CreatePtr to space address");

    assert!(wallet_res_err(&create_ptr_res).is_ok(), "CreatePtr tx should not error");


    // Confirm ptr binding.
    rig.mine_blocks(1, None).await?;
    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(ALICE).await?;

    // Compute SPTR from the (unchanged) space spk and verify it's indexed.
    let sptr = Sptr::from_spk::<Sha256>(current_spk.clone());
    let ptr_out = rig.spaced.client.get_ptr(sptr).await?;
    assert!(ptr_out.is_some(), "ptr lookup by SPTR should return a result for the space spk");


    let space = full_after.spaceout.space.expect("space");
    let delegation = rig.spaced.client.get_delegation(space.name.clone()).await?;
    assert_eq!(delegation, Some(sptr), "expected a delegation matching sptr");

    let delegator = rig.spaced.client.get_delegator(sptr).await?;
    assert_eq!(delegator, Some(space.name.clone()), "expected a delegator to match sptr");

    let commitments_tip = rig.spaced.client.get_commitment(space.name.clone(), None)
        .await.expect("commitment tip");
    assert!(commitments_tip.is_none(), "no initial commitment was made");
    
    // Make a commitment
    let create_commitment_res = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            space: space.name.clone(),
            root: sha256::Hash::from_slice(&[1u8;32]).expect("valid"),
        })],
        false,
    )
        .await
        .expect("commits");

    assert!(wallet_res_err(&create_commitment_res).is_ok(), "commit tx should not error");


    // Confirm commitment.
    rig.mine_blocks(1, None).await?;
    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(ALICE).await?;

    let commitments_tip = rig.spaced.client.get_commitment(space.name.clone(), None)
        .await.expect("commitment tip");
    assert!(commitments_tip.is_some(), "one commitment was made");
    let commitment = commitments_tip.unwrap();

    assert_eq!(commitment.state_root, [1u8;32], "there was a commitment");
    assert!(commitment.prev_root.is_none(), "no previous root");
    assert_eq!(commitment.history_hash, [1u8;32], "history hash must match initial commitment");


    // Make another commitment
    let create_commitment_res = wallet_do(
        rig,
        ALICE,
        vec![RpcWalletRequest::Commit(CommitParams {
            space: space.name.clone(),
            root: sha256::Hash::from_slice(&[2u8;32]).expect("valid"),
        })],
        false,
    )
        .await
        .expect("commits");

    assert!(wallet_res_err(&create_commitment_res).is_ok(), "commit tx should not error");

    // Confirm commitment.
    rig.mine_blocks(1, None).await?;
    rig.wait_until_synced().await?;
    rig.wait_until_wallet_synced(ALICE).await?;

    let commitments_tip = rig.spaced.client.get_commitment(space.name.clone(), None)
        .await.expect("commitment tip");
    let commitment = commitments_tip.unwrap();

    assert_eq!(commitment.state_root, [2u8;32], "tip must point to most recent commitment");
    assert_eq!(commitment.prev_root.clone(), Some([1u8;32]) , "prev should point to preview commitment");
    assert_eq!(commitment.history_hash, transcript_hash::<Sha256>([1u8;32], [2u8;32]),
               "history hash must commit to all commitments");


    let prev_commit =
        rig.spaced.client.get_commitment(
            space.name.clone(),
            Some(sha256::Hash::from_slice(
                commitment.prev_root.as_ref().expect("exists")
            ).expect("valid"))
        ).await.expect("prev_commitment");

    assert_eq!(
        prev_commit.map(|p| p.state_root),
        Some([1u8;32]),
        "previous commitment should continue to exist"
    );

    Ok(())
}

fn wallet_res_err(res: &WalletResponse) -> anyhow::Result<()> {
    for tx in &res.result {
        if let Some(e) = tx.error.as_ref() {
            let s = e.iter()
                .map(|(k, v)| format!("{k}:{v}"))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(anyhow!("{}", s));
        }
    }
    Ok(())
}

#[tokio::test]
async fn run_ptr_tests() -> anyhow::Result<()> {
    let rig = TestRig::new_with_regtest_preset().await?;
    let wallets_path = rig.testdata_wallets_path().await;

    let count = rig.get_block_count().await? as u32;
    assert!(count > 3000, "expected an initialized test set");

    rig.wait_until_synced().await?;
    load_wallet(&rig, wallets_path.clone(), ALICE).await?;
    load_wallet(&rig, wallets_path.clone(), BOB).await?;
    load_wallet(&rig, wallets_path, EVE).await?;

    it_should_create_sptrs(&rig)
        .await
        .expect("should open auction");

    it_should_operate_space(&rig).await.expect("should operate space");
    Ok(())
}

pub async fn load_wallet(rig: &TestRig, wallets_dir: PathBuf, name: &str) -> anyhow::Result<()> {
    let wallet_path = wallets_dir.join(format!("{name}.json"));
    let json = std::fs::read_to_string(wallet_path)?;
    let export = WalletExport::from_str(&json)?;
    rig.spaced.client.wallet_import(export).await?;
    Ok(())
}

async fn wallet_do(
    rig: &TestRig,
    wallet: &str,
    requests: Vec<RpcWalletRequest>,
    force: bool,
) -> anyhow::Result<WalletResponse> {
    let res = rig
        .spaced
        .client
        .wallet_send_request(
            wallet,
            RpcWalletTxBuilder {
                bidouts: None,
                requests,
                fee_rate: Some(FeeRate::from_sat_per_vb(1).expect("fee")),
                dust: None,
                force,
                confirmed_only: false,
                skip_tx_check: false,
            },
        )
        .await?;
    Ok(res)
}
