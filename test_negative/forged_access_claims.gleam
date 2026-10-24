// expect: Unknown module value
import hellhound/resource

pub fn main() {
  resource.AccessClaims(issuer: "https://evil", subject: "admin")
}
