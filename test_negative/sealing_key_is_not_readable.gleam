// expect: Unknown record field
import hellhound/config

pub fn main(key: config.SealingKey) -> BitArray {
  key.reveal()
}
