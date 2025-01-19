use netavark::network::netlink;

use netlink_packet_route::{address::AddressAttribute, link::LinkAttribute, link::LinkInfo, link::InfoKind};

use std::net::IpAddr;

pub fn get_ip_vrf(ip: IpAddr) -> Option<String> {

    let mut host = netlink::Socket::new().unwrap();

    let addresses = host.dump_addresses().unwrap();
    let mut address_index: Option<u32> = None;
 
    'address_loop: for address in addresses {
        for nla in address.attributes.iter() {
            if let AddressAttribute::Address(this_ip) = &nla {
                if *this_ip == ip {
                    address_index = Some(address.header.index);
                    break 'address_loop;
                }
            }
        }
        
    }
    let mut vrf_index : Option<u32>  = None;

    match address_index {
        Some(address_index) => {
            let ip_link_msg = host.get_link(netlink::LinkID::ID(address_index)).unwrap();
            for nla in ip_link_msg.attributes.iter() {
                if let LinkAttribute::Controller(index) = nla {
                    vrf_index = Some(*index);
                    break;
                }
            }
        },
        None => {
            return None;
        }
    }

    match vrf_index {
        Some(vrf_index) => {
            let vrf_link_msg = host.get_link(netlink::LinkID::ID(vrf_index)).unwrap();

            let mut vrf_name = "".to_string();
            let mut is_vrf = false;

            for nla in vrf_link_msg.attributes.iter() {
                if let LinkAttribute::IfName(name) = nla {
                    vrf_name = name.clone();
                }
                if let LinkAttribute::LinkInfo(info) = nla {
                    for inf in info.iter() {
                        if let LinkInfo::Kind(kind) = inf {
                            if *kind == InfoKind::Vrf {
                                is_vrf = true;
                                break;
                            }
                        }
                    }
                }
            }

            if is_vrf {
                return Some(vrf_name);
            }
        },
        None => {   }
    }    
    return None;
}