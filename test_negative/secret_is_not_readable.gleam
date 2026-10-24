// expect: Unknown record field
import hellhound/config

pub fn main(secret: config.Secret) -> String {
  secret.reveal()
}
