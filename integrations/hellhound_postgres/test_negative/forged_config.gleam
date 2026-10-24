// expect: Unknown module value
import hellhound_postgres

pub fn main(settings: hellhound_postgres.Config) -> hellhound_postgres.Config {
  hellhound_postgres.Config(..settings, schema: "forged")
}
