// expect: Type mismatch
import hellhound

pub fn main(info: hellhound.UserInfo) -> String {
  hellhound.subject(info)
}
