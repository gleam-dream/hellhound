// expect: Unknown module value
import hellhound

pub fn main() {
  hellhound.AccessToken(reveal: fn() { "token" }, token_type: "Bearer")
}
