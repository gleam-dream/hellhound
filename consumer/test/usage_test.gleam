//// Every usage example runs here against the local test provider.

import hellhound_reference/usage/callback_addresses
import hellhound_reference/usage/durable_store
import hellhound_reference/usage/resource_server
import hellhound_reference/usage/responsibilities
import hellhound_reference/usage/supervision
import hellhound_reference/usage/test_provider

pub fn supervision_test() {
  supervision.run()
}

pub fn durable_store_test() {
  durable_store.run()
}

pub fn conditional_writes_test() {
  durable_store.conditional_writes()
}

pub fn resource_server_test() {
  resource_server.run()
}

pub fn callback_addresses_test() {
  callback_addresses.run()
}

pub fn test_provider_test() {
  test_provider.run()
}

pub fn responsibilities_test() {
  responsibilities.run()
}
