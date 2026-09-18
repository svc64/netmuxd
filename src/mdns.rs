// Jackson Coxson

use crate::manager::ManagerRequest;
use crate::pairing_file::PairingFileFinder;
use crate::{config::NetmuxdConfig, manager::ManagerSender};
use log::{debug, warn};
use mdns_sd::{ServiceDaemon, ServiceEvent};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

const SERVICE_NAME: &str = "apple-mobdev2";
const SERVICE_PROTOCOL: &str = "tcp";

/// How often known services are handed to the manager again.
///
/// Resolve events arrive on mdns-sd's schedule, which has nothing to do with
/// whether we could use the last one: a pairing record written afterwards, or
/// a device asleep during its handshake, produces no new event. Services stay
/// in the set and are re-sent; the manager drops the ones it already has.
const RETRY_INTERVAL: Duration = Duration::from_secs(30);

pub async fn discover(sender: ManagerSender, config: NetmuxdConfig) {
    // mdns-sd expects the fully-qualified service type with a trailing '.';
    // downstream consumers expect the form without it.
    let browse_type = format!("_{}._{}.local.", SERVICE_NAME, SERVICE_PROTOCOL);
    let service_name = format!("_{}._{}.local", SERVICE_NAME, SERVICE_PROTOCOL);
    log::info!("Starting mDNS discovery for {browse_type} with mdns-sd");

    let daemon = match ServiceDaemon::new() {
        Ok(d) => d,
        Err(e) => {
            log::error!("Failed to create mDNS daemon: {e}");
            return;
        }
    };
    let receiver = match daemon.browse(&browse_type) {
        Ok(r) => r,
        Err(e) => {
            log::error!("Failed to start mDNS browse: {e}");
            return;
        }
    };

    let mut pairing_file_finder = PairingFileFinder::new(&config);
    let mut services: HashMap<String, mdns_sd::ResolvedService> = HashMap::new();
    let mut retry = tokio::time::interval(RETRY_INTERVAL);
    retry.tick().await; // the first tick completes immediately

    // Held across ticks instead of recreated each pass: `select!` drops the
    // branch it didn't take, and dropping a half-polled recv risks losing the
    // event it was waiting on.
    let recv = receiver.recv_async();
    tokio::pin!(recv);

    'discover: loop {
        tokio::select! {
            event = recv.as_mut() => {
                let Ok(event) = event else { break 'discover };
                recv.set(receiver.recv_async());

                match event {
                    ServiceEvent::ServiceResolved(resolved) => {
                        if announce(&sender, &mut pairing_file_finder, &resolved, &service_name)
                            .await
                            .is_err()
                        {
                            break 'discover;
                        }
                        services.insert(resolved.fullname.clone(), *resolved);
                    }
                    ServiceEvent::ServiceRemoved(_, fullname) => {
                        // Only stop retrying it. The heartbeat decides when a
                        // device is actually gone; a Bonjour goodbye can fire
                        // on a wifi roam while the connection is fine.
                        debug!("Service left the network: {fullname}");
                        services.remove(&fullname);
                    }
                    _ => {}
                }
            }
            _ = retry.tick() => {
                for service in services.values() {
                    if announce(&sender, &mut pairing_file_finder, service, &service_name)
                        .await
                        .is_err()
                    {
                        break 'discover;
                    }
                }
            }
        }
    }

    debug!("mDNS discovery loop stopped");
}

/// Hand a resolved service to the manager. `Err` means the manager is gone.
///
/// Not matching a pairing record isn't an error: the service stays in the
/// retry set so a record written later still gets picked up.
async fn announce(
    sender: &ManagerSender,
    pairing_file_finder: &mut PairingFileFinder,
    resolved: &mdns_sd::ResolvedService,
    service_name: &str,
) -> Result<(), ()> {
    debug!(
        "Resolved service: fullname={} addrs={:?}",
        resolved.fullname, resolved.addresses
    );

    let addr = match pick_address(resolved) {
        Some(a) => a,
        None => {
            warn!(
                "Resolved mDNS service has no usable address: {}",
                resolved.fullname
            );
            return Ok(());
        }
    };

    // iOS 26.4+: match by Bonjour TXT record (identifier + authTag HMACs).
    let identifier = resolved
        .get_property_val("identifier")
        .and_then(|v| v)
        .map(|b| b.to_vec());
    let auth_tags: Vec<Vec<u8>> = resolved
        .get_properties()
        .iter()
        .filter(|p| {
            let k = p.key();
            k == "authTag" || k.starts_with("authTag#")
        })
        .filter_map(|p| p.val().map(|b| b.to_vec()))
        .collect();

    let mut udid: Option<String> = None;
    if let Some(ident) = &identifier
        && !auth_tags.is_empty()
    {
        let refs: Vec<&[u8]> = auth_tags.iter().map(|v| v.as_slice()).collect();
        udid = pairing_file_finder.find_udid_from_txt(ident, &refs).await;
    }

    // iOS < 26.4 fallback: parse MAC out of the instance name (`<MAC>@<id>.…`).
    if udid.is_none()
        && let Some((mac_addr, _)) = resolved.fullname.split_once('@')
        && let Ok(u) = pairing_file_finder
            .get_udid_from_mac(mac_addr.to_string())
            .await
    {
        udid = Some(u);
    }

    let udid = match udid {
        Some(u) => u,
        None => {
            debug!(
                "No paired device matched service {} (identifier={}, authTags={})",
                resolved.fullname,
                identifier.is_some(),
                auth_tags.len()
            );
            return Ok(());
        }
    };

    sender
        .send(ManagerRequest::discovered_device(
            udid,
            addr,
            service_name.to_string(),
            "Network".to_string(),
        ))
        .await
        .map_err(|_| ())
}

fn pick_address(resolved: &mdns_sd::ResolvedService) -> Option<IpAddr> {
    // Prefer IPv4 to preserve the existing behaviour; fall back to any address.
    resolved
        .addresses
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| resolved.addresses.iter().next())
        .map(|a| a.to_ip_addr())
}
