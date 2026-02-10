use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "oci-manager",
    version,
    about = "OCI Compute manager (CLI + web UI)"
)]
pub struct Cli {
    #[arg(short, long, global = true, env = "OCI_PROFILE")]
    pub profile: Option<String>,
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    #[command(subcommand)]
    Instance(InstanceCommand),
    Availability(AvailabilityArgs),
    Serve(ServeArgs),
    /// Run a single create attempt (or retry loop) then exit.
    /// Designed for system cron / Windows Task Scheduler.
    Cron(CronArgs),
}

#[derive(Debug, Subcommand)]
pub enum InstanceCommand {
    List(InstanceListArgs),
    Create(InstanceCreateArgs),
    Terminate(InstanceTerminateArgs),
    Reboot(InstanceRebootArgs),
}

#[derive(Debug, Parser)]
pub struct InstanceListArgs {
    #[arg(long)]
    pub compartment: Option<String>,
}

#[derive(Debug, Parser)]
pub struct InstanceCreateArgs {
    #[arg(long)]
    pub compartment: Option<String>,
    #[arg(long)]
    pub subnet: Option<String>,
    #[arg(long)]
    pub shape: Option<String>,
    #[arg(long)]
    pub ocpus: Option<f64>,
    #[arg(long = "memory-gbs")]
    pub memory_in_gbs: Option<f64>,
    #[arg(long = "boot-volume-gbs")]
    pub boot_volume_size_gbs: Option<u64>,
    #[arg(long = "availability-domain")]
    pub availability_domain: Option<String>,
    #[arg(long)]
    pub image: Option<String>,
    #[arg(long = "image-os")]
    pub image_os: Option<String>,
    #[arg(long = "image-version")]
    pub image_version: Option<String>,
    #[arg(long = "display-name")]
    pub display_name: Option<String>,
    #[arg(long = "ssh-key")]
    pub ssh_key: Option<String>,
    #[arg(long)]
    pub retry: bool,
    #[arg(long)]
    pub retry_seconds: Option<u64>,
    #[arg(long)]
    pub retry_max: Option<u32>,
}

#[derive(Debug, Parser)]
pub struct InstanceTerminateArgs {
    #[arg(long)]
    pub instance: String,
}

#[derive(Debug, Parser)]
pub struct InstanceRebootArgs {
    #[arg(long)]
    pub instance: String,
    #[arg(long)]
    pub hard: bool,
}

#[derive(Debug, Parser)]
pub struct AvailabilityArgs {
    #[arg(long)]
    pub compartment: Option<String>,
    #[arg(long = "availability-domain")]
    pub availability_domain: Option<String>,
}

#[derive(Debug, Parser)]
pub struct ServeArgs {
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,
    #[arg(long, default_value = "9927")]
    pub port: u16,
    #[arg(long, env = "OCI_ADMIN_KEY")]
    pub admin_key: Option<String>,
    #[arg(long)]
    pub allow_remote: bool,
}

#[derive(Debug, Parser)]
pub struct CronArgs {
    #[arg(long)]
    pub compartment: Option<String>,
    #[arg(long)]
    pub subnet: Option<String>,
    #[arg(long)]
    pub shape: Option<String>,
    #[arg(long)]
    pub ocpus: Option<f64>,
    #[arg(long = "memory-gbs")]
    pub memory_in_gbs: Option<f64>,
    #[arg(long = "boot-volume-gbs")]
    pub boot_volume_size_gbs: Option<u64>,
    #[arg(long = "availability-domain")]
    pub availability_domain: Option<String>,
    #[arg(long)]
    pub image: Option<String>,
    #[arg(long = "image-os")]
    pub image_os: Option<String>,
    #[arg(long = "image-version")]
    pub image_version: Option<String>,
    #[arg(long = "display-name")]
    pub display_name: Option<String>,
    #[arg(long = "ssh-key")]
    pub ssh_key: Option<String>,
    /// Preset name from config (e.g. ARM-1cpu-6gb-Ubuntu)
    #[arg(long)]
    pub preset: Option<String>,
    /// Keep retrying on failure
    #[arg(long)]
    pub retry: bool,
    /// Seconds between retries (default 180)
    #[arg(long, default_value = "180")]
    pub retry_seconds: u64,
    /// Max retry attempts (0 = unlimited)
    #[arg(long, default_value = "0")]
    pub retry_max: u32,
}
