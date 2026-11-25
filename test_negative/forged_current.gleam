// expect: Unknown module value
import hellhound

pub fn main(session: hellhound.Session) {
  hellhound.Current(session: session, issued_at: 0)
}
