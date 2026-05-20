use std::collections::HashMap;
use blake2::{Blake2s256, Digest};

pub type GroupId = [u8; 32];
pub type IdentityPublicKey = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GroupRole {
    Founder,
    Admin,
    Moderator,
    Member,
}

pub struct MemberInfo {
    pub role: GroupRole,
    pub joined_at: u64,
    pub identity_pk: IdentityPublicKey,
}

/// Signal-style Sender Key for a single group member.
/// Each member holds their own chain key; ratcheting it produces per-message keys.
pub struct SenderKey {
    pub chain_key: [u8; 32],
    pub iteration: u32,
}

impl SenderKey {
    pub fn new(initial_key: [u8; 32]) -> Self {
        Self { chain_key: initial_key, iteration: 0 }
    }

    /// Ratchets the sender key forward, returning a fresh message key.
    /// This provides forward secrecy: compromising a future key does NOT reveal past messages.
    pub fn ratchet(&mut self) -> [u8; 32] {
        // Domain-separated BLAKE2s derivation (consistent with zero-session/ratchet.rs)
        let mut h_chain = Blake2s256::new();
        h_chain.update(b"zero-group-chain");
        h_chain.update(&self.chain_key);
        
        let mut h_msg = Blake2s256::new();
        h_msg.update(b"zero-group-message");
        h_msg.update(&self.chain_key);

        let mut next_chain = [0u8; 32];
        let mut msg_key = [0u8; 32];
        next_chain.copy_from_slice(&h_chain.finalize());
        msg_key.copy_from_slice(&h_msg.finalize());

        self.chain_key = next_chain;
        self.iteration += 1;
        msg_key
    }
}

/// Manages a Signal-style group chat session with per-member Sender Keys.
pub struct GroupSession {
    pub group_id: GroupId,
    pub my_role: GroupRole,
    pub members: HashMap<IdentityPublicKey, MemberInfo>,
    /// Our own sender key (used for outgoing messages)
    pub my_sender_key: SenderKey,
    /// Sender keys received from each peer (used to decrypt their messages)
    pub peer_sender_keys: HashMap<IdentityPublicKey, SenderKey>,
    /// Admin and founder public keys (for role enforcement)
    pub admin_keys: Vec<IdentityPublicKey>,
}

impl GroupSession {
    pub fn new(group_id: GroupId, my_role: GroupRole, initial_key: [u8; 32]) -> Self {
        Self {
            group_id,
            my_role,
            members: HashMap::new(),
            my_sender_key: SenderKey::new(initial_key),
            peer_sender_keys: HashMap::new(),
            admin_keys: Vec::new(),
        }
    }

    /// Adds a member to the group. Only Founders and Admins can perform this action.
    pub fn add_member(&mut self, identity_pk: IdentityPublicKey, role: GroupRole, joined_at: u64) -> Result<(), &'static str> {
        if self.my_role > GroupRole::Admin {
            return Err("Insufficient permissions to add members");
        }
        self.members.insert(identity_pk, MemberInfo { role, joined_at, identity_pk });
        Ok(())
    }

    /// Registers a peer's sender key so we can decrypt their messages.
    pub fn register_peer_sender_key(&mut self, peer_pk: IdentityPublicKey, key: [u8; 32]) {
        self.peer_sender_keys.insert(peer_pk, SenderKey::new(key));
    }

    /// Ratchets our outgoing chain and returns the message key for the next message.
    pub fn next_outgoing_key(&mut self) -> [u8; 32] {
        self.my_sender_key.ratchet()
    }

    /// Ratchets a peer's chain to get the decryption key for their next message.
    pub fn next_incoming_key(&mut self, peer_pk: &IdentityPublicKey) -> Option<[u8; 32]> {
        self.peer_sender_keys.get_mut(peer_pk).map(|sk| sk.ratchet())
    }

    pub fn remove_member(&mut self, identity_pk: &IdentityPublicKey) -> Result<(), &'static str> {
        if self.my_role > GroupRole::Admin {
            return Err("Insufficient permissions to remove members");
        }
        if let Some(target) = self.members.get(identity_pk) {
            if target.role <= self.my_role {
                return Err("Cannot remove a member with equal or higher role");
            }
        } else {
            return Err("Member not found");
        }
        self.members.remove(identity_pk);
        self.peer_sender_keys.remove(identity_pk);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_key(seed: u8) -> IdentityPublicKey {
        [seed; 32]
    }

    fn make_group(role: GroupRole) -> GroupSession {
        GroupSession::new([0u8; 32], role, [1u8; 32])
    }

    // ── Role Enforcement ──────────────────────────────────────────────────

    #[test]
    fn test_founder_can_add_members() {
        let mut gs = make_group(GroupRole::Founder);
        assert!(gs.add_member(make_key(1), GroupRole::Member, 0).is_ok());
    }

    #[test]
    fn test_admin_can_add_members() {
        let mut gs = make_group(GroupRole::Admin);
        assert!(gs.add_member(make_key(1), GroupRole::Member, 0).is_ok());
    }

    #[test]
    fn test_moderator_cannot_add_members() {
        let mut gs = make_group(GroupRole::Moderator);
        assert!(gs.add_member(make_key(1), GroupRole::Member, 0).is_err());
    }

    #[test]
    fn test_member_cannot_add_members() {
        let mut gs = make_group(GroupRole::Member);
        assert!(gs.add_member(make_key(1), GroupRole::Member, 0).is_err());
    }

    #[test]
    fn test_admin_cannot_remove_founder() {
        let mut gs = make_group(GroupRole::Admin);
        gs.add_member(make_key(1), GroupRole::Founder, 0).ok(); // forced bypass for test setup
        // Manually insert a "founder" member to try to remove
        gs.members.insert(make_key(99), MemberInfo {
            role: GroupRole::Founder,
            joined_at: 0,
            identity_pk: make_key(99),
        });
        // Admin (my_role = Admin) trying to remove Founder (target.role = Founder)
        // target.role (Founder) <= self.my_role (Admin) => blocked
        let result = gs.remove_member(&make_key(99));
        assert!(result.is_err(), "Admin should not be able to remove a Founder");
    }

    #[test]
    fn test_admin_can_remove_member() {
        let mut gs = make_group(GroupRole::Admin);
        gs.members.insert(make_key(5), MemberInfo {
            role: GroupRole::Member,
            joined_at: 0,
            identity_pk: make_key(5),
        });
        assert!(gs.remove_member(&make_key(5)).is_ok());
        assert!(!gs.members.contains_key(&make_key(5)));
    }

    #[test]
    fn test_remove_nonexistent_member_errors() {
        let mut gs = make_group(GroupRole::Admin);
        assert!(gs.remove_member(&make_key(99)).is_err());
    }

    // ── Sender Key Ratchet ────────────────────────────────────────────────

    #[test]
    fn test_sender_key_ratchet_produces_unique_keys() {
        let mut sk = SenderKey::new([0u8; 32]);
        let k1 = sk.ratchet();
        let k2 = sk.ratchet();
        let k3 = sk.ratchet();
        assert_ne!(k1, k2);
        assert_ne!(k2, k3);
    }

    #[test]
    fn test_sender_key_ratchet_is_deterministic() {
        let seed = [42u8; 32];
        let mut sk1 = SenderKey::new(seed);
        let mut sk2 = SenderKey::new(seed);
        assert_eq!(sk1.ratchet(), sk2.ratchet());
        assert_eq!(sk1.ratchet(), sk2.ratchet());
    }

    #[test]
    fn test_sender_key_iteration_increments() {
        let mut sk = SenderKey::new([0u8; 32]);
        assert_eq!(sk.iteration, 0);
        sk.ratchet();
        assert_eq!(sk.iteration, 1);
        sk.ratchet();
        assert_eq!(sk.iteration, 2);
    }

    #[test]
    fn test_peer_sender_key_registration_and_ratchet() {
        let mut gs = make_group(GroupRole::Founder);
        let peer = make_key(7);
        gs.register_peer_sender_key(peer, [0xAA; 32]);
        let k = gs.next_incoming_key(&peer);
        assert!(k.is_some());
    }

    #[test]
    fn test_unknown_peer_returns_none() {
        let mut gs = make_group(GroupRole::Founder);
        let k = gs.next_incoming_key(&make_key(0xFF));
        assert!(k.is_none());
    }
}
