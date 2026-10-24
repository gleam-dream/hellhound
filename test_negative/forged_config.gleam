// expect: Unknown module value
import hellhound/config

pub fn main() {
  config.Config(issuer: "http://evil")
}
