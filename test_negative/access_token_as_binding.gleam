// expect: Type mismatch
import hellhound

pub fn main(client: hellhound.Client, token: hellhound.AccessToken) {
  hellhound.complete_login(client, token)
}
