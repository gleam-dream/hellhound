// expect: Unknown module value
import hellhound/config
pub fn main() {
  config.SigningKey("forged")
}
