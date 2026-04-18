//! Auction resolution logic.
//!
//! The enclave receives encrypted sealed bids from the chain, decrypts them,
//! determines the winner (highest bidder) and the second price, and returns
//! an attested result.

use cosmwasm_std::{Addr, HexBinary, Uint128};
use k256::ecdsa::SigningKey;
use sealed_auction_contract::msg::{ResolveMsg, SealedBid};
use tonic::Status;

/// Decrypt a sealed bid ciphertext using the enclave's session key.
fn decrypt_bid(sk: &SigningKey, ciphertext: &HexBinary) -> Result<SealedBid, Status> {
    let plaintext =
        ecies::decrypt(&sk.to_bytes(), ciphertext).map_err(|e| Status::internal(e.to_string()))?;
    serde_json::from_slice(&plaintext)
        .map_err(|e| Status::internal(format!("malformed bid: {e}")))
}

/// Run the Vickrey (second-price sealed-bid) auction logic.
///
/// 1. Decrypt each sealed bid
/// 2. Find the highest bidder
/// 3. The winner pays the second-highest bid (or reserve if only one bidder)
///
/// Bids below the reserve price are ignored.
pub fn resolve_auction(
    sk: &SigningKey,
    round_id: u64,
    reserve_price: Uint128,
    bids: Vec<(Addr, HexBinary)>,
) -> Result<ResolveMsg, Status> {
    // Decrypt all bids, skip any that fail decryption
    let mut decrypted: Vec<(Addr, Uint128)> = Vec::new();
    for (addr, ciphertext) in &bids {
        match decrypt_bid(sk, ciphertext) {
            Ok(bid) if bid.amount >= reserve_price => {
                decrypted.push((addr.clone(), bid.amount));
            }
            Ok(_) => {
                // Bid below reserve, ignore
            }
            Err(_) => {
                // Malformed ciphertext, ignore
            }
        }
    }

    let bid_count = bids.len() as u32;

    if decrypted.is_empty() {
        return Ok(ResolveMsg {
            round_id,
            winner: None,
            price: Uint128::zero(),
            bid_count,
        });
    }

    // Sort descending by amount
    decrypted.sort_by(|a, b| b.1.cmp(&a.1));

    let winner = decrypted[0].0.clone();

    // Second price: max(second_highest_bid, reserve_price)
    let second_highest = if decrypted.len() >= 2 {
        decrypted[1].1
    } else {
        Uint128::zero()
    };
    let price = second_highest.max(reserve_price);

    Ok(ResolveMsg {
        round_id,
        winner: Some(winner.to_string()),
        price,
        bid_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::VerifyingKey;
    use rand::rngs::OsRng;

    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::random(&mut OsRng);
        let vk = VerifyingKey::from(&sk);
        (sk, vk)
    }

    fn encrypt_bid(vk: &VerifyingKey, amount: u128) -> HexBinary {
        let bid = SealedBid {
            amount: Uint128::new(amount),
        };
        let plaintext = serde_json::to_vec(&bid).unwrap();
        let ciphertext = ecies::encrypt(&vk.to_sec1_bytes(), &plaintext).unwrap();
        ciphertext.into()
    }

    #[test]
    fn test_single_bidder_pays_reserve() {
        let (sk, vk) = test_keypair();
        let reserve = Uint128::new(100);

        let bids = vec![(Addr::unchecked("sponsor1"), encrypt_bid(&vk, 500))];

        let result = resolve_auction(&sk, 1, reserve, bids).unwrap();
        assert_eq!(result.winner, Some("sponsor1".to_string()));
        assert_eq!(result.price, Uint128::new(100)); // pays reserve (no second bidder)
    }

    #[test]
    fn test_two_bidders_second_price() {
        let (sk, vk) = test_keypair();
        let reserve = Uint128::new(100);

        let bids = vec![
            (Addr::unchecked("sponsor1"), encrypt_bid(&vk, 200)),
            (Addr::unchecked("sponsor2"), encrypt_bid(&vk, 500)),
        ];

        let result = resolve_auction(&sk, 1, reserve, bids).unwrap();
        assert_eq!(result.winner, Some("sponsor2".to_string()));
        assert_eq!(result.price, Uint128::new(200)); // pays second highest
    }

    #[test]
    fn test_bid_below_reserve_ignored() {
        let (sk, vk) = test_keypair();
        let reserve = Uint128::new(100);

        let bids = vec![
            (Addr::unchecked("low"), encrypt_bid(&vk, 50)), // below reserve
            (Addr::unchecked("high"), encrypt_bid(&vk, 300)),
        ];

        let result = resolve_auction(&sk, 1, reserve, bids).unwrap();
        assert_eq!(result.winner, Some("high".to_string()));
        assert_eq!(result.price, Uint128::new(100)); // pays reserve (only valid bidder)
        assert_eq!(result.bid_count, 2); // both submitted, one below reserve
    }

    #[test]
    fn test_no_valid_bids() {
        let (sk, vk) = test_keypair();
        let reserve = Uint128::new(1000);

        let bids = vec![
            (Addr::unchecked("low1"), encrypt_bid(&vk, 50)),
            (Addr::unchecked("low2"), encrypt_bid(&vk, 99)),
        ];

        let result = resolve_auction(&sk, 1, reserve, bids).unwrap();
        assert!(result.winner.is_none());
        assert_eq!(result.price, Uint128::zero());
    }

    #[test]
    fn test_three_bidders() {
        let (sk, vk) = test_keypair();
        let reserve = Uint128::new(100);

        let bids = vec![
            (Addr::unchecked("a"), encrypt_bid(&vk, 150)),
            (Addr::unchecked("b"), encrypt_bid(&vk, 300)),
            (Addr::unchecked("c"), encrypt_bid(&vk, 200)),
        ];

        let result = resolve_auction(&sk, 1, reserve, bids).unwrap();
        assert_eq!(result.winner, Some("b".to_string()));
        assert_eq!(result.price, Uint128::new(200)); // c's bid is second highest
    }

    #[test]
    fn test_malformed_ciphertext_ignored() {
        let (sk, vk) = test_keypair();
        let reserve = Uint128::new(100);

        let bids = vec![
            (Addr::unchecked("good"), encrypt_bid(&vk, 500)),
            (Addr::unchecked("bad"), HexBinary::from(vec![0xDE, 0xAD])), // garbage
        ];

        let result = resolve_auction(&sk, 1, reserve, bids).unwrap();
        assert_eq!(result.winner, Some("good".to_string()));
        assert_eq!(result.bid_count, 2);
    }
}
