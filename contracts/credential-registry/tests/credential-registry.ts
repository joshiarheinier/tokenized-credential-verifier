import * as anchor from "@anchor-lang/core";
import { BN, Program } from "@anchor-lang/core";
import { assert } from "chai";
import { randomBytes } from "crypto";
import { CredentialRegistry } from "../target/types/credential_registry";

const { Keypair, PublicKey, LAMPORTS_PER_SOL } = anchor.web3;

const CREDENTIAL_ACTIVE = 0;
const CREDENTIAL_REVOKED = 1;

describe("credential-registry", () => {
  anchor.setProvider(anchor.AnchorProvider.env());
  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const program = anchor.workspace.credentialRegistry as Program<CredentialRegistry>;
  const admin = (provider.wallet as anchor.Wallet).payer;

  const pda = (...seeds: Buffer[]) =>
    PublicKey.findProgramAddressSync(seeds, program.programId);

  const [registryConfig, registryBump] = pda(Buffer.from("registry_config"));
  const [programData] = PublicKey.findProgramAddressSync(
    [program.programId.toBuffer()],
    new PublicKey("BPFLoaderUpgradeab1e11111111111111111111111")
  );
  const issuerPda = (issuerId: Buffer) =>
    pda(Buffer.from("issuer"), issuerId)[0];
  const credentialPda = (ref: Buffer) =>
    pda(Buffer.from("credential"), ref)[0];

  const now = () => Math.floor(Date.now() / 1000);
  const inOneHour = () => new BN(now() + 3600);

  async function fund(kp: anchor.web3.Keypair) {
    const sig = await provider.connection.requestAirdrop(
      kp.publicKey,
      LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(sig, "confirmed");
    return kp;
  }

  async function expectFailure(p: Promise<unknown>, pattern: RegExp) {
    try {
      await p;
    } catch (e) {
      assert.match(String(e), pattern);
      return;
    }
    assert.fail("expected the transaction to fail");
  }

  // Shared fixtures, created in order by the describes below.
  const issuerId = randomBytes(32);
  const issuerRecord = issuerPda(issuerId);
  const signingKey = Keypair.generate().publicKey;
  let issuerAuthority: anchor.web3.Keypair;
  let outsider: anchor.web3.Keypair;

  before(async () => {
    issuerAuthority = await fund(Keypair.generate());
    outsider = await fund(Keypair.generate());
  });

  const registerIssuer = (id: Buffer, signer = admin) =>
    program.methods
      .registerIssuer(
        [...id],
        signingKey,
        issuerAuthority.publicKey
      )
      .accountsPartial({
        authority: signer.publicKey,
        registryConfig,
        issuerRecord: issuerPda(id),
      })
      .signers([signer])
      .rpc();

  const registerCredential = (
    ref: Buffer,
    expiresAt: anchor.BN,
    signer = issuerAuthority,
    record = issuerRecord
  ) =>
    program.methods
      .registerCredential([...ref], expiresAt)
      .accountsPartial({
        authority: signer.publicKey,
        registryConfig,
        issuerRecord: record,
        credentialStatus: credentialPda(ref),
      })
      .signers([signer])
      .rpc();

  const revokeCredential = (
    ref: Buffer,
    signer: anchor.web3.Keypair,
    record = issuerRecord
  ) =>
    program.methods
      .revokeCredential()
      .accountsPartial({
        authority: signer.publicKey,
        registryConfig,
        issuerRecord: record,
        credentialStatus: credentialPda(ref),
      })
      .signers([signer])
      .rpc();

  const setIssuerStatus = (active: boolean, signer = admin) =>
    program.methods
      .setIssuerStatus(active)
      .accountsPartial({
        authority: signer.publicKey,
        registryConfig,
        issuerRecord,
      })
      .signers([signer])
      .rpc();

  const setPaused = (paused: boolean, signer = admin) =>
    program.methods
      .setPaused(paused)
      .accountsPartial({ authority: signer.publicKey, registryConfig })
      .signers([signer])
      .rpc();

  describe("initialize_registry", () => {
    it("rejects a signer that is not the upgrade authority", async () => {
      await expectFailure(
        program.methods
          .initializeRegistry()
          .accountsPartial({
            authority: outsider.publicKey,
            registryConfig,
            programData,
          })
          .signers([outsider])
          .rpc(),
        /NotUpgradeAuthority/
      );
    });

    it("initializes the registry with the upgrade authority", async () => {
      await program.methods
        .initializeRegistry()
        .accountsPartial({ registryConfig, programData })
        .rpc();

      const config = await program.account.registryConfig.fetch(registryConfig);
      assert.isTrue(config.authority.equals(admin.publicKey));
      assert.isFalse(config.paused);
      assert.equal(config.version, 1);
      assert.equal(config.bump, registryBump);
    });

    it("rejects a second initialization", async () => {
      await expectFailure(
        program.methods
          .initializeRegistry()
          .accountsPartial({ registryConfig, programData })
          .rpc(),
        /already in use|custom program error: 0x0/
      );
    });
  });

  describe("register_issuer", () => {
    it("rejects a non-authority signer", async () => {
      await expectFailure(
        program.methods
          .registerIssuer([...issuerId], signingKey, outsider.publicKey)
          .accountsPartial({
            authority: outsider.publicKey,
            registryConfig,
            issuerRecord,
          })
          .signers([outsider])
          .rpc(),
        /Unauthorized/
      );
    });

    it("rejects the default pubkey as issuer authority", async () => {
      const id = randomBytes(32);
      await expectFailure(
        program.methods
          .registerIssuer([...id], signingKey, PublicKey.default)
          .accountsPartial({
            registryConfig,
            issuerRecord: issuerPda(id),
          })
          .rpc(),
        /InvalidAuthority/
      );
    });

    it("registers an issuer and stores the record", async () => {
      await registerIssuer(issuerId);

      const rec = await program.account.issuerRecord.fetch(issuerRecord);
      assert.deepEqual(rec.issuerId, [...issuerId]);
      assert.isTrue(rec.issuerSigningKey.equals(signingKey));
      assert.isTrue(rec.authority.equals(issuerAuthority.publicKey));
      assert.isTrue(rec.active);
      assert.isAbove(rec.createdAt.toNumber(), 0);
      assert.equal(rec.bump, pda(Buffer.from("issuer"), issuerId)[1]);
    });

    it("rejects registering the same issuer twice", async () => {
      await expectFailure(
        registerIssuer(issuerId),
        /already in use|custom program error: 0x0/
      );
    });

    it("derives the issuer PDA deterministically", () => {
      assert.isTrue(issuerPda(issuerId).equals(issuerRecord));
      assert.isFalse(issuerPda(randomBytes(32)).equals(issuerRecord));
    });
  });

  describe("register_credential", () => {
    const ref = randomBytes(32);

    it("rejects a signer that is not the issuer authority", async () => {
      await expectFailure(
        registerCredential(randomBytes(32), inOneHour(), outsider),
        /Unauthorized/
      );
    });

    it("rejects the registry authority acting as the issuer", async () => {
      await expectFailure(
        registerCredential(randomBytes(32), inOneHour(), admin),
        /Unauthorized/
      );
    });

    it("rejects an expiry in the past", async () => {
      await expectFailure(
        registerCredential(randomBytes(32), new BN(now() - 10)),
        /ExpiryInPast/
      );
    });

    it("registers an active credential", async () => {
      const expiresAt = inOneHour();
      await registerCredential(ref, expiresAt);

      const status = await program.account.credentialStatus.fetch(
        credentialPda(ref)
      );
      assert.deepEqual(status.credentialRef, [...ref]);
      assert.deepEqual(status.issuerId, [...issuerId]);
      assert.equal(status.status, CREDENTIAL_ACTIVE);
      assert.equal(status.expiresAt.toString(), expiresAt.toString());
    });

    it("rejects a duplicate credential_ref", async () => {
      await expectFailure(
        registerCredential(ref, inOneHour()),
        /already in use|custom program error: 0x0/
      );
    });
  });

  describe("set_issuer_status", () => {
    it("rejects a non-authority signer", async () => {
      await expectFailure(setIssuerStatus(false, outsider), /Unauthorized/);
    });

    it("rejects a no-op transition", async () => {
      await expectFailure(setIssuerStatus(true), /StatusUnchanged/);
    });

    it("blocks credential registration while suspended, then allows it after reactivation", async () => {
      await setIssuerStatus(false);
      assert.isFalse(
        (await program.account.issuerRecord.fetch(issuerRecord)).active
      );
      await expectFailure(
        registerCredential(randomBytes(32), inOneHour()),
        /IssuerInactive/
      );

      await setIssuerStatus(true);
      assert.isTrue(
        (await program.account.issuerRecord.fetch(issuerRecord)).active
      );
      await registerCredential(randomBytes(32), inOneHour());
    });
  });

  describe("revoke_credential", () => {
    it("lets the issuer authority revoke, and rejects a second revocation", async () => {
      const ref = randomBytes(32);
      await registerCredential(ref, inOneHour());

      await revokeCredential(ref, issuerAuthority);
      const status = await program.account.credentialStatus.fetch(
        credentialPda(ref)
      );
      assert.equal(status.status, CREDENTIAL_REVOKED);

      await expectFailure(
        revokeCredential(ref, issuerAuthority),
        /CredentialAlreadyRevoked/
      );
    });

    it("lets the registry authority revoke", async () => {
      const ref = randomBytes(32);
      await registerCredential(ref, inOneHour());
      await revokeCredential(ref, admin);
      const status = await program.account.credentialStatus.fetch(
        credentialPda(ref)
      );
      assert.equal(status.status, CREDENTIAL_REVOKED);
    });

    it("rejects an unrelated signer", async () => {
      const ref = randomBytes(32);
      await registerCredential(ref, inOneHour());
      await expectFailure(revokeCredential(ref, outsider), /Unauthorized/);
      const status = await program.account.credentialStatus.fetch(
        credentialPda(ref)
      );
      assert.equal(status.status, CREDENTIAL_ACTIVE);
    });

    it("rejects revoking via a different issuer's record", async () => {
      // A second issuer whose authority tries to revoke the first issuer's credential.
      const otherId = randomBytes(32);
      const otherAuthority = await fund(Keypair.generate());
      await program.methods
        .registerIssuer([...otherId], signingKey, otherAuthority.publicKey)
        .accountsPartial({ registryConfig, issuerRecord: issuerPda(otherId) })
        .rpc();

      const ref = randomBytes(32);
      await registerCredential(ref, inOneHour());
      await expectFailure(
        revokeCredential(ref, otherAuthority, issuerPda(otherId)),
        /CredentialIssuerMismatch/
      );
    });

    it("still allows revocation while the issuer is suspended", async () => {
      const ref = randomBytes(32);
      await registerCredential(ref, inOneHour());
      await setIssuerStatus(false);
      await revokeCredential(ref, issuerAuthority);
      await setIssuerStatus(true);
      const status = await program.account.credentialStatus.fetch(
        credentialPda(ref)
      );
      assert.equal(status.status, CREDENTIAL_REVOKED);
    });
  });

  describe("set_paused", () => {
    it("rejects a non-authority signer", async () => {
      await expectFailure(setPaused(true, outsider), /Unauthorized/);
    });

    it("blocks new issuers and credentials but not revocation or suspension", async () => {
      const ref = randomBytes(32);
      await registerCredential(ref, inOneHour());

      await setPaused(true);
      assert.isTrue(
        (await program.account.registryConfig.fetch(registryConfig)).paused
      );

      await expectFailure(registerIssuer(randomBytes(32)), /RegistryPaused/);
      await expectFailure(
        registerCredential(randomBytes(32), inOneHour()),
        /RegistryPaused/
      );
      await revokeCredential(ref, issuerAuthority);
      await setIssuerStatus(false);
      await setIssuerStatus(true);

      await setPaused(false);
      await registerCredential(randomBytes(32), inOneHour());
    });
  });

  describe("update_registry_authority", () => {
    const update = (newAuthority: anchor.web3.PublicKey, signer = admin) =>
      program.methods
        .updateRegistryAuthority(newAuthority)
        .accountsPartial({ authority: signer.publicKey, registryConfig })
        .signers([signer])
        .rpc();

    it("rejects a non-authority signer", async () => {
      await expectFailure(update(outsider.publicKey, outsider), /Unauthorized/);
    });

    it("rejects the default pubkey", async () => {
      await expectFailure(update(PublicKey.default), /InvalidAuthority/);
    });

    it("hands over administration and revokes the old authority's powers", async () => {
      const next = await fund(Keypair.generate());
      await update(next.publicKey);

      const config = await program.account.registryConfig.fetch(registryConfig);
      assert.isTrue(config.authority.equals(next.publicKey));

      await expectFailure(setPaused(true, admin), /Unauthorized/);
      await expectFailure(registerIssuer(randomBytes(32), admin), /Unauthorized/);

      // The new authority can administer, and can hand control back.
      await setPaused(true, next);
      await setPaused(false, next);
      await update(admin.publicKey, next);
      assert.isTrue(
        (await program.account.registryConfig.fetch(registryConfig)).authority.equals(
          admin.publicKey
        )
      );
    });
  });
});
