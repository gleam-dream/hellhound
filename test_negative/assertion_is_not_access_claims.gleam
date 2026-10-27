// expect: Type mismatch
import hellhound/assertion
import hellhound/resource
pub fn main(value: assertion.Assertion) {
  resource.subject(value)
}
