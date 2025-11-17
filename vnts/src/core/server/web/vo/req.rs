use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

#[derive(Debug, Serialize, Deserialize)]  
pub struct RouteConfigReq {  
    pub vnt_cli_ip: String,      // vnt-cli的虚拟IP  
    pub lan_network: String,      // 内网网段 (CIDR格式)  
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateWGData {
    pub group_id: String,
    pub virtual_ip: String,
    pub device_id: String,
    pub name: String,
    pub config: CreateWgConfig,
    // 路由配置列表（可选）  
    pub routes: Option<Vec<RouteConfigReq>>,  
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateWgConfig {
    pub vnts_endpoint: String,
    pub private_key: String,
    pub persistent_keepalive: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginData {
    pub username: String,
    pub password: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveClientReq {
    pub group_id: String,
    pub virtual_ip: Option<Ipv4Addr>,
}
