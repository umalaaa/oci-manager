mod cli;
mod config;
mod logic;
mod models;
mod oci;
mod web;

use anyhow::{bail, Result};
use clap::Parser;
use std::net::IpAddr;
use tracing_subscriber::EnvFilter;

use crate::cli::{AvailabilityArgs, Command, CronArgs, InstanceCommand};
use crate::config::OciConfig;
use crate::logic::{resolve_create_payload, CreateInput};
use crate::oci::OciClient;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let cli = cli::Cli::parse();
    let config = OciConfig::load(cli.config)?;
    let profile_name = cli.profile.clone().unwrap_or_else(|| "DEFAULT".to_string());
    let profile = config.profile(Some(&profile_name))?;

    match cli.command {
        Command::Instance(cmd) => {
            let client = OciClient::new(profile.clone())?;
            handle_instance(cmd, &client, &profile).await?
        }
        Command::Availability(args) => {
            let args = *args;
            let client = OciClient::new(profile.clone())?;
            handle_availability(args, &client, &profile).await?
        }
        Command::Serve(args) => {
            let args = *args;
            if !profile.enable_admin {
                bail!("Web UI is disabled. Set enable_admin=true in config.");
            }
            let admin_key = args
                .admin_key
                .or_else(|| profile.admin_key.clone())
                .and_then(|value| {
                    let trimmed = value.trim().to_string();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed)
                    }
                });
            if admin_key.is_none() {
                bail!("admin_key is required when enable_admin=true (set admin_key in config or OCI_ADMIN_KEY).");
            }
            if !args.allow_remote && !is_loopback_host(&args.host) {
                bail!("Refusing to bind to non-loopback address without --allow-remote.");
            }
            let port = if args.port != 9927 {
                args.port
            } else {
                profile.port.unwrap_or(args.port)
            };
            web::serve(config, profile_name, admin_key, args.host, port).await?;
        }
        Command::Cron(args) => {
            let args = *args;
            let client = OciClient::new(profile.clone())?;
            handle_cron(args, &client, &profile, &config).await?
        }
    }

    Ok(())
}

async fn handle_instance(
    command: InstanceCommand,
    client: &OciClient,
    profile: &config::Profile,
) -> Result<()> {
    match command {
        InstanceCommand::List(args) => {
            let compartment = args
                .compartment
                .or_else(|| profile.defaults.compartment.clone())
                .ok_or_else(|| anyhow::anyhow!("Missing compartment OCID"))?;
            let instances = client.list_instances(&compartment).await?;
            if instances.is_empty() {
                println!("No instances found");
            } else {
                for instance in instances {
                    println!(
                        "{}\t{}\t{}\t{}",
                        instance.id,
                        instance.lifecycle_state,
                        instance.display_name,
                        instance.shape
                    );
                }
            }
        }
        InstanceCommand::Create(args) => {
            let args = *args;
            let retry_enabled =
                args.retry || args.retry_seconds.is_some() || args.retry_max.is_some();
            let retry_seconds = args.retry_seconds.unwrap_or(180);
            let mut attempt: u32 = 0;
            loop {
                attempt += 1;
                let input = CreateInput {
                    profile: None, // CLI uses --profile global arg, handled outside
                    compartment: args.compartment.clone(),
                    subnet: args.subnet.clone(),
                    shape: args.shape.clone(),
                    ocpus: args.ocpus,
                    memory_in_gbs: args.memory_in_gbs,
                    boot_volume_size_gbs: args.boot_volume_size_gbs,
                    availability_domain: args.availability_domain.clone(),
                    image: args.image.clone(),
                    image_os: args.image_os.clone(),
                    image_version: args.image_version.clone(),
                    display_name: args.display_name.clone(),
                    ssh_key: args.ssh_key.clone(),
                };
                let resolved =
                    resolve_create_payload(client, &profile.defaults, input, true).await?;
                println!(
                    "Creating instance in {} with shape {} (attempt {})",
                    resolved.availability_domain, resolved.shape, attempt
                );
                match client.create_instance(resolved.payload).await {
                    Ok(instance) => {
                        println!(
                            "Instance created: {} ({})",
                            instance.display_name, instance.id
                        );
                        break;
                    }
                    Err(err) => {
                        if !retry_enabled {
                            return Err(err);
                        }
                        if let Some(max) = args.retry_max {
                            if attempt >= max {
                                return Err(err);
                            }
                        }
                        println!(
                            "Create failed: {}. Retrying in {} seconds...",
                            err, retry_seconds
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(retry_seconds)).await;
                    }
                }
            }
        }
        InstanceCommand::Terminate(args) => {
            client.terminate_instance(&args.instance).await?;
            println!("Instance terminated: {}", args.instance);
        }
        InstanceCommand::Reboot(args) => {
            client.reboot_instance(&args.instance, args.hard).await?;
            println!("Instance rebooted: {}", args.instance);
        }
    }
    Ok(())
}

async fn handle_availability(
    args: AvailabilityArgs,
    client: &OciClient,
    profile: &config::Profile,
) -> Result<()> {
    let compartment = args
        .compartment
        .or_else(|| profile.defaults.compartment.clone())
        .ok_or_else(|| anyhow::anyhow!("Missing compartment OCID"))?;
    let ads = client.availability_domains(&compartment).await?;
    println!("Availability Domains:");
    for ad in &ads {
        println!("{} ({})", ad.name, ad.id);
    }
    let ad_name = args
        .availability_domain
        .or_else(|| profile.defaults.availability_domain.clone());
    if let Some(ad) = ad_name {
        let shapes = client.list_shapes(&compartment, &ad).await?;
        println!("\nShapes in {}:", ad);
        for shape in shapes {
            let ocpus = shape.ocpus.unwrap_or_default();
            let mem = shape.memory_in_gbs.unwrap_or_default();
            println!("{} - {} OCPUs / {} GB", shape.shape, ocpus, mem);
        }
    }
    Ok(())
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

async fn handle_cron(
    args: CronArgs,
    client: &OciClient,
    profile: &config::Profile,
    config: &OciConfig,
) -> Result<()> {
    // Merge preset values if --preset is given
    let preset = if let Some(preset_name) = &args.preset {
        config
            .presets
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(preset_name))
    } else {
        None
    };

    let mut attempt: u32 = 0;
    loop {
        attempt += 1;
        let input = CreateInput {
            profile: None,
            compartment: args
                .compartment
                .clone()
                .or_else(|| preset.and_then(|p| p.compartment.clone())),
            subnet: args
                .subnet
                .clone()
                .or_else(|| preset.and_then(|p| p.subnet.clone())),
            shape: args
                .shape
                .clone()
                .or_else(|| preset.and_then(|p| p.shape.clone())),
            ocpus: args.ocpus.or_else(|| preset.and_then(|p| p.ocpus)),
            memory_in_gbs: args
                .memory_in_gbs
                .or_else(|| preset.and_then(|p| p.memory_in_gbs)),
            boot_volume_size_gbs: args
                .boot_volume_size_gbs
                .or_else(|| preset.and_then(|p| p.boot_volume_size_gbs)),
            availability_domain: args
                .availability_domain
                .clone()
                .or_else(|| preset.and_then(|p| p.availability_domain.clone())),
            image: args
                .image
                .clone()
                .or_else(|| preset.and_then(|p| p.image.clone())),
            image_os: args
                .image_os
                .clone()
                .or_else(|| preset.and_then(|p| p.image_os.clone())),
            image_version: args
                .image_version
                .clone()
                .or_else(|| preset.and_then(|p| p.image_version.clone())),
            display_name: args.display_name.clone().or_else(|| {
                preset.and_then(|p| {
                    p.display_name_prefix.as_ref().map(|prefix| {
                        let ts = time::OffsetDateTime::now_utc()
                            .format(&time::format_description::well_known::Rfc3339)
                            .unwrap_or_else(|_| "now".to_string());
                        format!("{}-{}", prefix, ts.replace(':', ""))
                    })
                })
            }),
            ssh_key: args
                .ssh_key
                .clone()
                .or_else(|| preset.and_then(|p| p.ssh_public_key.clone())),
        };

        let resolved = resolve_create_payload(client, &profile.defaults, input, true).await?;
        println!(
            "[cron] Creating instance in {} with shape {} (attempt {})",
            resolved.availability_domain, resolved.shape, attempt
        );

        match client.create_instance(resolved.payload).await {
            Ok(instance) => {
                println!(
                    "[cron] Instance created: {} ({})",
                    instance.display_name, instance.id
                );
                return Ok(());
            }
            Err(err) => {
                if !args.retry {
                    return Err(err);
                }
                if args.retry_max > 0 && attempt >= args.retry_max {
                    return Err(err);
                }
                println!(
                    "[cron] Create failed: {}. Retrying in {} seconds...",
                    err, args.retry_seconds
                );
                tokio::time::sleep(std::time::Duration::from_secs(args.retry_seconds)).await;
            }
        }
    }
}
