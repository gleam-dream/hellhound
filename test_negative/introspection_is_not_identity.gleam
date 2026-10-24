// expect: Type mismatch
import hellhound

pub fn main(info: hellhound.TokenInfo) -> String {
  hellhound.subject(info)
}
