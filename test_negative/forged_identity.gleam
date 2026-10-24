// expect: Unknown module value
import gleam/dynamic
import hellhound

pub fn main() {
  hellhound.VerifiedIdentity(
    issuer: "https://idp",
    subject: "s",
    claims: dynamic.nil(),
  )
}
