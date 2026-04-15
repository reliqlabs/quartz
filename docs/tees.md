# TEEs

## Why TEEs?

TEEs allow you to do things that cryptography alone doesn't -- like verifiable
data deletion, decentralized front-end hosting, collusion resistance, etc.

They also let you overcome current deficiencies and inefficiencies in
cryptographic solutions. TEEs are best seen as complements to a cryptographic stack.

A major motivation for TEEs is private computation. There are really only two ways to do computation on private data: MPC and TEEs.

- MPC is still highly inefficient for complex transactions.
- FHE is just a way to accelerate MPC (trading off network IO for compute). It's not a privacy solution for blockchains on its own.
- ZKP provide privacy from the verifier but not from the prover. Producing a ZKP privately either requires MPC or a TEE.
- Ideal stack combines all privacy technologies as appropriate.

The goal with Quartz is to provide a simple framework for getting started using
TEEs with an eye towards reducing dependency on the TEE as much as possible
(using light client protocols, ZKPs, etc.)

## Quartz TEE Stack

Quartz currently uses **Intel TDX** via **dstack** confidential VMs. This
replaces the previous Intel SGX + Gramine approach.

Key differences:
- TDX provides full VM isolation (vs. SGX process-level enclaves)
- Standard Docker containers instead of Gramine manifests
- Attestation verified via zkdcap Groth16 proofs (not on-chain DCAP contracts)
- dstack KMS provides deterministic key derivation

## Resources on TEE Security

See also the following talks:

- Andrew Miller - [The TEE Stack][tee-stack]
- Sylvain Bellemare - [Moving Towards Open Source & Verifiable Secure-through-Physics TEE Chips][bellemare-tee-salon]
- Ethan Buchman - [How to Win Friends and TEE-fluence People][how-to-win-friends]

[how-to-win-friends]: https://www.youtube.com/watch?v=XwKIt5XYyqw
[tee-stack]: https://www.youtube.com/watch?v=9AwlMB8TF4o
[bellemare-tee-salon]: https://www.youtube.com/watch?v=j6pGxMfffdA
