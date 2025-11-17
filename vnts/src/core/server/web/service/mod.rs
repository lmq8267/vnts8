use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::path::PathBuf; 

use anyhow::{anyhow, Context};
use base64::engine::general_purpose;
use base64::Engine;
use crossbeam_utils::atomic::AtomicCell;
use ipnetwork::Ipv4Network;
use rsa::rand_core::RngCore;

use crate::core::entity::{WireGuardConfig, RouteConfig};

use crate::core::server::web::vo::req::{CreateWGData, CreateWgConfig, LoginData, RemoveClientReq, RouteConfigReq};
use crate::core::server::web::vo::res::{
    ClientInfo, ClientStatusInfo, NetworkInfo, WGData, WgConfig, RouteConfigRes,
};
use crate::core::service::server::{generate_ip, RegisterClientRequest};
use crate::core::store::cache::AppCache;
use crate::ConfigInfo;

#[derive(Clone)]
pub struct VntsWebService {
    cache: AppCache,
    config: ConfigInfo,
    login_time: Arc<AtomicCell<(Instant, usize)>>,
}

impl VntsWebService {
    pub fn new(cache: AppCache, config: ConfigInfo) -> Self {
        Self {
            cache,
            config,
            login_time: Arc::new(AtomicCell::new((Instant::now(), 0))),
        }
    }
}

impl VntsWebService {
    pub async fn login(&self, login_data: LoginData) -> Result<String, String> {
        let (time, count) = self.login_time.load();
        if count >= 3 && time.elapsed() < Duration::from_secs(60) {
            return Err("一分钟后再试".into());
        }
        if login_data.username == self.config.username
            && login_data.password == self.config.password
        {
            self.login_time.store((time, 0));
            let auth = uuid::Uuid::new_v4().to_string().replace("-", "");
            self.cache
                .auth_map
                .insert(auth.clone(), (), Duration::from_secs(3600 * 24))
                .await;
            Ok(auth)
        } else {
            self.login_time.store((Instant::now(), count + 1));
            Err("账号或密码错误".into())
        }
    }
    pub fn check_auth(&self, auth: &String) -> bool {
        self.cache.auth_map.get(auth).is_some()
    }

    pub fn remove_client(&self, req: RemoveClientReq) {  
        if let Some(ip) = req.virtual_ip {  
            if let Some(network_info) = self.cache.virtual_network.get(&req.group_id) {  
                if let Some(client_info) = network_info.write().clients.remove(&ip.into()) {  
                    if let Some(key) = client_info.wireguard {  
                        self.cache.wg_group_map.remove(&key);  
                        // 删除后保存配置 
                        if let Err(e) = self.cache.save_wg_configs() {  
                            log::warn!("修改WireGuard配置失败: {:?}", e);  
                        }  
                    }  
                }  
            }  
        } else {  
            if let Some(network_info) = self.cache.virtual_network.remove(&req.group_id) {  
                for (_, client_info) in network_info.write().clients.drain() {  
                    if let Some(key) = client_info.wireguard {  
                        self.cache.wg_group_map.remove(&key);  
                    }  
                }  
                // 删除后保存配置 
                if let Err(e) = self.cache.save_wg_configs() {  
                    log::warn!("修改WireGuard配置失败: {:?}", e);  
                }  
            }  
        }  
    }
    pub fn gen_wg_private_key(&self) -> String {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        return general_purpose::STANDARD.encode(bytes);
    }
    pub async fn create_wg_config(&self, wg_data: CreateWGData) -> anyhow::Result<WGData> {
        let device_id = wg_data.device_id.trim().to_string();
        let group_id = wg_data.group_id.trim().to_string();
        if group_id.is_empty() {
            Err(anyhow!("组网id不能为空"))?;
        }
        if device_id.is_empty() {
            Err(anyhow!("设备id不能为空"))?;
        }
        let cache = &self.cache;
        let (secret_key, public_key) = Self::check_wg_config(&wg_data.config)?;
        let gateway = self.config.gateway;
        let netmask = self.config.netmask;
        let network = Ipv4Network::with_netmask(gateway, netmask)?;
        let network = Ipv4Network::with_netmask(network.network(), netmask)?;
        let virtual_ip = if wg_data.virtual_ip.trim().is_empty() {
            Ipv4Addr::UNSPECIFIED
        } else {
            Ipv4Addr::from_str(&wg_data.virtual_ip).context("虚拟IP错误")?
        };
        // 检查IP是否已被使用  
        if virtual_ip != Ipv4Addr::UNSPECIFIED {  
            // 检查是否被WireGuard客户端使用  
            let ip_used_by_wg = self.cache.wg_group_map  
                .iter()  
                .any(|entry| {  
                    let config = entry.value();  
                    config.group_id == group_id && config.ip == virtual_ip  
                });  
          
            if ip_used_by_wg {  
                Err(anyhow!("该IP已被WireGuard客户端使用"))?;  
            }  
          
            // 检查是否被普通客户端使用  
            if let Some(network_info) = self.cache.virtual_network.get(&group_id) {  
                let guard = network_info.read();  
                if guard.clients.contains_key(&virtual_ip.into()) {  
                    Err(anyhow!("该IP已被其他客户端使用"))?;  
                }  
            }  
        }
        // 解析和验证路由配置  
        let mut routes = Vec::new();  
        let mut allowed_ips = vec![network.to_string()];  
        // 检查组网是否已存在，如果存在且网段与服务端默认不同，则添加实际网段  
        if let Some(network_info) = cache.virtual_network.get(&group_id) {  
            let guard = network_info.read();  
            let actual_network_ip = Ipv4Addr::from(guard.network_ip);  
            let actual_mask_ip = Ipv4Addr::from(guard.mask_ip);  
      
            // 计算实际网段的 CIDR 表示  
            if let Ok(actual_network) = Ipv4Network::with_netmask(actual_network_ip, actual_mask_ip) {  
                let actual_network_str = actual_network.to_string();  
          
                // 如果实际网段与服务端默认网段不同，添加到 AllowedIPs  
                if actual_network_str != network.to_string() {  
                    allowed_ips.push(actual_network_str);  
                }  
            }  
        }  
      
        if let Some(route_configs) = &wg_data.routes {  
            for route_req in route_configs {  
                // 解析 vnt-cli 虚拟IP  
                let vnt_cli_ip = Ipv4Addr::from_str(&route_req.vnt_cli_ip)  
                    .context(format!("无效的vnt-cli虚拟IP: {}", route_req.vnt_cli_ip))?;  
              
                // 只有当组网已存在时，才验证 vnt-cli IP 是否在该组网的网段内  
                if let Some(network_info) = cache.virtual_network.get(&group_id) {  
                    let guard = network_info.read();  
                    let vnt_cli_ip_u32 = u32::from(vnt_cli_ip);  
                  
                    // 使用组网实际的网段信息进行验证  
                    if (vnt_cli_ip_u32 & guard.mask_ip) != guard.network_ip {  
                        let group_network = Ipv4Addr::from(guard.network_ip);  
                        let group_netmask = Ipv4Addr::from(guard.mask_ip);  
                        Err(anyhow!(  
                            "vnt-cli虚拟IP {} 不在当前组网的网段范围内 {}/{}",  
                            vnt_cli_ip,  
                            group_network,  
                            group_netmask  
                        ))?;  
                    }  
                }  
                // 如果组网不存在（首次创建WireGuard客户端），则不进行网段验证  
              
                // 解析内网网段（CIDR格式）  
                let lan_network_str = route_req.lan_network.trim();  
                let _lan_network = Ipv4Network::from_str(lan_network_str)  
                    .context(format!("无效的内网网段格式: {}", lan_network_str))?;  
              
                // 添加到路由配置  
                routes.push(RouteConfig {  
                    vnt_cli_ip,  
                    lan_network: lan_network_str.to_string(),  
                });  
              
                // 添加到 AllowedIPs  
                allowed_ips.push(lan_network_str.to_string());  
            }  
        } 
      
        let vnts_allowed_ips = allowed_ips.join(", "); 
        
        let register_client_request = RegisterClientRequest {
            group_id: group_id.clone(),
            virtual_ip,
            gateway,
            netmask,
            allow_ip_change: false,
            device_id: device_id.clone(),
            version: String::from("wg"),
            name: wg_data.name.clone(),
            client_secret: true,
            client_secret_hash: vec![],
            server_secret: true,
            address: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into(),
            tcp_sender: None,
            online: false,
            wireguard: Some(public_key),
        };
        let response = generate_ip(cache, register_client_request).await?;
        // 如果这是该组网的第一个客户端，根据分配的 IP 更新网段信息  
        if let Some(network_info) = cache.virtual_network.get(&group_id) {  
            let mut guard = network_info.write();  
            if guard.clients.len() == 1 {  
                // 这是第一个客户端，根据分配的 IP 更新网段  
                let actual_network = u32::from(response.virtual_ip) & u32::from(netmask);  
                guard.network_ip = actual_network;  
                log::info!(  
                    "更新组网 {} 的网段信息: network={}, mask={}, gateway={}",  
                    group_id,  
                    Ipv4Addr::from(actual_network),  
                    netmask,  
                    gateway  
                );  
            }  
        }  
        let wireguard_config = WireGuardConfig {
            vnts_endpoint: wg_data.config.vnts_endpoint.clone(),
            vnts_allowed_ips: vnts_allowed_ips.clone(),
            group_id: group_id.clone(),
            device_id: device_id.clone(),
            ip: response.virtual_ip,
            prefix: network.prefix(),
            persistent_keepalive: wg_data.config.persistent_keepalive,
            secret_key,
            public_key,
            routes: routes.clone(), 
        };
        
        cache.wg_group_map.insert(public_key, wireguard_config.clone());  
        
        // 更新 NetworkInfo 的路由表  
        if let Some(network_info) = cache.virtual_network.get(&group_id) {  
            let mut guard = network_info.write();  
          
            // 解析路由配置为路由表格式  
            let mut route_entries = Vec::new();  
            for route in &routes {  
                if let Ok(lan_net) = Ipv4Network::from_str(&route.lan_network) {  
                    let dest = u32::from(lan_net.network());  
                    let mask = u32::from(lan_net.mask());  
                    route_entries.push((dest, mask, route.vnt_cli_ip));  
                }  
            }  
          
            // 将路由条目存储到 NetworkInfo 的路由表中  
            guard.route_table.insert(public_key, route_entries);  
            guard.epoch += 1;  
        }
        
        // 保存配置到文件  
        if let Err(e) = cache.save_wg_configs() {  
            log::warn!("保存WireGuard配置失败: {:?}", e);  
        }
        let config = WgConfig {
            vnts_endpoint: wg_data.config.vnts_endpoint,
            vnts_public_key: general_purpose::STANDARD.encode(&self.config.wg_public_key),
            vnts_allowed_ips,
            public_key: general_purpose::STANDARD.encode(public_key),
            private_key: general_purpose::STANDARD.encode(secret_key),
            ip: response.virtual_ip,
            prefix: network.prefix(),
            persistent_keepalive: wg_data.config.persistent_keepalive,
            routes: routes.iter().map(|r| RouteConfigRes {  
                vnt_cli_ip: r.vnt_cli_ip,  
                lan_network: r.lan_network.clone(),  
            }).collect(),
        };
        let wg_data = WGData {
            group_id,
            virtual_ip: response.virtual_ip,
            device_id,
            name: wg_data.name,
            config,
        };
        Ok(wg_data)
    }
    fn check_wg_config(config: &CreateWgConfig) -> anyhow::Result<([u8; 32], [u8; 32])> {
        match config.vnts_endpoint.to_socket_addrs() {
            Ok(mut addr) => {
                if let Some(addr) = addr.next() {
                    if addr.ip().is_unspecified() || addr.port() == 0 {
                        Err(anyhow!("服务端地址错误"))?
                    }
                }
            }
            Err(e) => Err(anyhow!("服务端地址解析失败:{}", e))?,
        }

        let private_key = general_purpose::STANDARD
            .decode(&config.private_key)
            .context("私钥错误")?;
        let private_key: [u8; 32] = private_key.try_into().map_err(|_| anyhow!("私钥错误"))?;
        let secret_key = boringtun::x25519::StaticSecret::from(private_key);
        let public_key = *boringtun::x25519::PublicKey::from(&secret_key).as_bytes();

        Ok((private_key, public_key))
    }
    pub fn group_info(&self, group: String) -> Option<NetworkInfo> {
        if let Some(info) = self.cache.virtual_network.get(&group) {
            let guard = info.read();
            let mut network = NetworkInfo::new(
                guard.network_ip.into(),
                guard.mask_ip.into(),
                guard.gateway_ip.into(),
                general_purpose::STANDARD.encode(&self.config.wg_public_key),
            );
            for info in guard.clients.values() {
                let address = match info.address {
                    SocketAddr::V4(_) => info.address,
                    SocketAddr::V6(ipv6) => {
                        if let Some(ipv4) = ipv6.ip().to_ipv4_mapped() {
                            SocketAddr::V4(SocketAddrV4::new(ipv4, ipv6.port()))
                        } else {
                            info.address
                        }
                    }
                };
                let status_info = if let Some(client_status) = &info.client_status {
                    Some(ClientStatusInfo {
                        p2p_list: client_status.p2p_list.clone(),
                        up_stream: client_status.up_stream,
                        down_stream: client_status.down_stream,
                        is_cone: client_status.is_cone,
                        update_time: format!(
                            "{}",
                            client_status.update_time.format("%Y-%m-%d %H:%M:%S")
                        ),
                    })
                } else {
                    None
                };
                let mut wg_config = None;
                if let Some(key) = &info.wireguard {
                    if let Some(v) = self.cache.wg_group_map.get(key) {
                        wg_config.replace(v.clone());
                    }
                }
                let client_info = ClientInfo {
                    device_id: info.device_id.clone(),
                    version: info.version.clone(),
                    name: info.name.clone(),
                    client_secret: info.client_secret,
                    server_secret: info.server_secret,
                    address,
                    online: info.online,
                    virtual_ip: info.virtual_ip.into(),
                    status_info,
                    last_join_time: info.last_join_time.format("%Y-%m-%d %H:%M:%S").to_string(),
                    wg_config: wg_config.map(|v| v.into()),
                };
                network.clients.push(client_info);
            }
            network
                .clients
                .sort_by(|v1, v2| v1.virtual_ip.cmp(&v2.virtual_ip));
            Some(network)
        } else {
            None
        }
    }
    pub fn is_group_list_disabled(&self) -> bool {  
        self.config.disable_group_list  
    }  
  
    pub fn get_group_list(&self) -> Vec<String> {  
        self.cache  
            .virtual_network  
            .key_values()  
            .into_iter()  
            .map(|(key, _)| key)  
            .collect() 
    }
}
