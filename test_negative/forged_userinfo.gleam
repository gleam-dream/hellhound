// expect: Unknown module value
import gleam/dynamic
import hellhound

pub fn main() {
  hellhound.UserInfo(subject: "s", claims: dynamic.nil())
}
