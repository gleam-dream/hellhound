// expect: Type mismatch
import hellhound

pub fn main(session: hellhound.Session) -> hellhound.VerifiedIdentity {
  hellhound.current_claims(hellhound.session_identity(session))
}
