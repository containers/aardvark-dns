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
    // Map of IP address to DNS server IPs to service queries not handled
    // directly.
    // Not implemented in initial version, we will always use host resolvers.
    //ctr_dns: HashMap<IpAddr, Vec<IpAddr>>,
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
    // TODO: If we want to optimize even more strongly, we can probably avoid
    // the clone() calls here.
    pub fn new(
        containers: &HashMap<IpAddr, Vec<String>>,
        networks: &HashMap<String, HashMap<String, Vec<IpAddr>>>,
    ) -> DNSBackend {
        DNSBackend {
            ip_mappings: containers.clone(),
            name_mappings: networks.clone(),
        }
    }

    // Handle a single DNS lookup made by a given IP.
    // The name being looked up *must* have the TLD used by the DNS server
    // stripped.
    // TODO: right now this returns v4 and v6 addresses intermixed and relies on
    // the caller to sort through them; we could add a v6 bool as an argument
    // and do it here instead.
    pub fn lookup(&self, requester: &IpAddr, mut name: &str) -> DNSResult {
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
            if name.len() > 0 && name.chars().last().unwrap() == '.' {
                name = &name[0..name.len() - 1];
            }
            if let Some(addrs) = net_names.get(name) {
                results.append(&mut addrs.clone());
            }
        }

        if results.len() == 0 {
            return DNSResult::NXDomain;
        }

        DNSResult::Success(results)
    }

    // reverse lookup must return a single name resolved via mapping
    pub fn reverse_lookup(&self, requester: &IpAddr, lookup_ip: &str) -> Vec<String> {
        let nets = match self.ip_mappings.get(requester) {
            Some(n) => n,
            None => return Vec::<String>::new(),
        };

        let mut result_vec = Vec::<String>::new();

        for net in nets {
            let net_names = match self.name_mappings.get(net) {
                Some(n) => n,
                None => {
                    error!("Container with IP {} belongs to network {} but there is no listing in networks table!", requester.to_string(), net);
                    continue;
                }
            };

            for (container_name, ip_list) in net_names {
                for ip in ip_list {
                    if ip.to_string() == lookup_ip {
                        result_vec.push(container_name.to_owned().to_string());
                    }
                }
            }
        }

        return result_vec;
    }
}
