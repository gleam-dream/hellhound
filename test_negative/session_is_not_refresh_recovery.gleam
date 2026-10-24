// expect: Type mismatch
import hellhound

pub fn main(client: hellhound.Client, session: hellhound.Session) {
  hellhound.recover_refresh(client, session)
}
