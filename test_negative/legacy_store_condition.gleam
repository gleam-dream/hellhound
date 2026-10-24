// expect: WriteCondition
import gleam/option.{None}
import hellhound/store

pub fn main(records: store.Store, record: store.Record) {
  store.put(records, record, None)
}
