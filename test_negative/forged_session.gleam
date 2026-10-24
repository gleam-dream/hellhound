// expect: Unknown module value
import hellhound

pub fn main(identity: hellhound.VerifiedIdentity) {
  hellhound.Session(identity: identity, reference: "r", revision: 1, provider: "p")
}
