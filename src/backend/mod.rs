use log::error;
use std::collections::HashMap;
use std::net::IpAddr;
use std::vec::Vec;

// The core structure of the in-memory backing store for the DNS server.
// TODO: I've initially intermingled v4 and v6 addresses for simplicity; the
// server will get back a mix of responses and filter for v4/v6 from there.
// This may not be a good decision, not sure yet; we can split later if
// necessary.
pub struct DNSBackend {
    // Map of IP -> Network membership.
    // Every container must have an entry in this map, otherwise we will not
    // service requests to the Podman TLD for it.
    pub ip_mappings: HashMap<IpAddr, Vec<String>>,
    // Map of network name to map of name to IP addresses.
    pub name_mappings: HashMap<String, HashMap<String, Vec<IpAddr>>>,
    // Map of network name to map of IP address to container name.
    pub reverse_mappings: HashMap<String, HashMap<IpAddr, Vec<String>>>,
    // Map of IP address to DNS server IPs to service queries not handled
    // directly.
    pub ctr_dns_server: HashMap<IpAddr, Option<Vec<IpAddr>>>,
    // Map of network name and DNS server IPs.
    pub network_dns_server: HashMap<String, Vec<IpAddr>>,
}

pub enum DNSResult {
    // We know the IP address of the requester and what networks they are in.
    // Here's a vector of IPs corresponding to your query.
    Success(Vec<IpAddr>),
    // We know the IP address of the requester and what networks they are in.
    // However, there were no results for the requested name to look up.
    NXDomain,
    // We do not know the IP address of the requester.
    NoSuchIP,
    // Other, unspecified error occurred.
    Error(String),
}

impl DNSBackend {
    // Create a new backend from the given set of network mappings.
    pub fn new(
        containers: HashMap<IpAddr, Vec<String>>,
        networks: HashMap<String, HashMap<String, Vec<IpAddr>>>,
        reverse: HashMap<String, HashMap<IpAddr, Vec<String>>>,
        ctr_dns_server: HashMap<IpAddr, Option<Vec<IpAddr>>>,
        network_dns_server: HashMap<String, Vec<IpAddr>>,
    ) -> DNSBackend {
        DNSBackend {
            ip_mappings: containers,
            name_mappings: networks,
            reverse_mappings: reverse,
            ctr_dns_server,
            network_dns_server,
        }
    }

    // Handle a single DNS lookup made by a given IP.
    // The name being looked up *must* have the TLD used by the DNS server
    // stripped.
    // TODO: right now this returns v4 and v6 addresses intermixed and relies on
    // the caller to sort through them; we could add a v6 bool as an argument
    // and do it here instead.
    pub fn lookup(&self, requester: &IpAddr, entry: &str) -> DNSResult {
        // Normalize lookup entry to lowercase.
        let mut name = entry.to_lowercase();
        let nets = match self.ip_mappings.get(requester) {
            Some(n) => n,
            None => return DNSResult::NoSuchIP,
        };

        let mut results: Vec<IpAddr> = Vec::new();

        for net in nets {
            let net_names = match self.name_mappings.get(net) {
                Some(n) => n,
                None => {
                    error!("Container with IP {} belongs to network {} but there is no listing in networks table!", requester.to_string(), net);
                    continue;
                }
            };
            // if this is a fully qualified name, remove dots so backend can perform search
            if !name.is_empty() {
                if let Some(lastchar) = name.chars().last() {
                    if lastchar == '.' {
                        name = (name[0..name.len() - 1]).to_string();
                    }
                }
            }
            if let Some(addrs) = net_names.get(&name) {
                results.append(&mut addrs.clone());
            }
        }

        if results.is_empty() {
            return DNSResult::NXDomain;
        }

        DNSResult::Success(results)
    }

    // Returns list of network resolvers for a particular container
    pub fn get_network_scoped_resolvers(&self, requester: &IpAddr) -> Option<Vec<IpAddr>> {
        let mut results: Vec<IpAddr> = Vec::new();

        match self.ip_mappings.get(requester) {
            Some(nets) => {
                for net in nets {
                    match self.network_dns_server.get(net) {
                        Some(resolvers) => results.extend_from_slice(resolvers),
                        None => {
                            continue;
                        }
                    };
                }
            }
            None => return None,
        };

        Some(results)
    }

    /// Return a single name resolved via mapping if it exists.
    pub fn reverse_lookup(&self, requester: &IpAddr, lookup_ip: &IpAddr) -> Option<&Vec<String>> {
        let nets = match self.ip_mappings.get(requester) {
            Some(n) => n,
            None => return None,
        };

        for ips in nets.iter().filter_map(|v| self.reverse_mappings.get(v)) {
            if let Some(names) = ips.get(lookup_ip) {
                return Some(names);
            }
        }

        None
    }
}
