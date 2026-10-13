// expect: Unknown module value
import warden_postgres

pub fn main(settings: warden_postgres.Config) -> warden_postgres.Config {
  warden_postgres.Config(..settings, schema: "forged")
}
