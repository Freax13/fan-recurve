use std::{
    collections::{hash_map::Entry, BTreeMap, BTreeSet, HashMap},
    ffi::{c_void, CStr},
    fmt,
    fs::read_dir,
    io,
    path::PathBuf,
};

use anyhow::{anyhow, bail, ensure, Context, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use nix::{sys::ptrace, unistd::Pid};
use serde::{de::Visitor, ser::SerializeMap, Deserialize, Deserializer, Serialize, Serializer};
use tracing::{debug, info};

fn main() -> Result<()> {
    tracing_subscriber::fmt::fmt()
        .with_writer(io::stderr)
        .init();

    let cli = Cli::parse();

    let pid = find_target_process(&cli).context("couldn't find target process")?;
    let ipmi_base = get_ipmi_base(pid)
        .context("couldn't get libipmi base address")?
        .context("couldn't find libipmi base address")?;
    hijack(&cli, pid, ipmi_base)?;

    Ok(())
}

fn find_target_process(cli: &Cli) -> Result<Pid> {
    let pid = list_processes()?
        .into_iter()
        .find(|&pid| {
            let Ok(executable) = get_executable(pid) else { return false; };
            executable == cli.target_process
        })
        .with_context(|| anyhow!("process {} doesn't exit", cli.target_process.display()))?;
    info!(%pid, "found target process");
    Ok(pid)
}

#[derive(Parser)]
#[command(version, author)]
struct Cli {
    /// Change the fan curves in this process.
    #[arg(long, default_value = "/bin/ipmi_sensor")]
    target_process: PathBuf,
    #[command(subcommand)]
    subcommand: CliSubcommand,
}

#[derive(Subcommand)]
enum CliSubcommand {
    Dump(DumpCommand),
    Patch(PatchCommand),
}

/// Dump the fan curves.
///
/// By default the curves for all fan modes for all sensors in all zones will
/// be dumped.
/// The `zone`, `sensor` and `fan-mode` arguments can be used to restrict the
/// dump to only a subset.
#[derive(Args)]
pub struct DumpCommand {
    /// A file to save the dump to.
    #[arg(short, long)]
    file: Option<PathBuf>,
    /// Dump sensors in this zone.
    #[arg(short, long)]
    zone: Option<Vec<u8>>,
    /// Dump fan curves for this sensors.
    #[arg(short, long)]
    sensor: Option<Vec<String>>,
    /// Dump the given fan modes.
    #[arg(long, value_enum)]
    fan_mode: Option<Vec<FanMode>>,
}

/// Patch the fan curves.
#[derive(Args)]
pub struct PatchCommand {
    /// A file to load a dump from.
    #[arg(short, long)]
    file: PathBuf,
}

fn list_processes() -> Result<Vec<Pid>> {
    let mut results = Vec::new();
    let mut read_dir = read_dir("/proc/")?;
    while let Some(entry) = read_dir.next().transpose()? {
        let Ok(s) = entry.file_name().into_string() else { continue; };
        let Ok(s) = s.parse::<i32>() else { continue; };
        results.push(Pid::from_raw(s));
    }
    Ok(results)
}

fn get_ipmi_base(pid: Pid) -> Result<Option<u32>> {
    let path = format!("/proc/{pid}/maps");
    let maps = std::fs::read_to_string(path)?;
    let Some(line) = maps.lines().find(|line| line.ends_with("/lib/libipmi.so")) else { return Ok(None) };
    let (base, _) = line
        .split_once('-')
        .context("the line should start with a base address")?;
    let base = u32::from_str_radix(base, 16)?;
    info!(
        ipmi_base = format_args!("{base:#x}"),
        "found base address of libipmi"
    );
    Ok(Some(base))
}

fn get_executable(pid: Pid) -> Result<PathBuf> {
    let path = format!("/proc/{pid}/exe");
    std::fs::read_link(path).context("failed to read link")
}

fn hijack(cli: &Cli, pid: Pid, ipmi_base: u32) -> Result<()> {
    // Attach to the process.
    debug!(%pid, "attaching to proccess");
    ptrace::attach(pid)?;

    // Execute the command.
    let res = do_hijack(cli, pid, ipmi_base);

    // Detach from the process.
    debug!(%pid, "dettaching from proccess");
    ptrace::detach(pid, None)?;

    // Return the result from executing the command
    res
}

fn do_hijack(cli: &Cli, pid: Pid, ipmi_base: u32) -> Result<()> {
    const BOARD_GLOBAL_OFFSET: u32 = 0x29618c;

    let board_address = ptrace::read(pid, (ipmi_base + BOARD_GLOBAL_OFFSET) as *mut c_void)?;
    let board_address = board_address as u32;
    info!(
        board_address = format_args!("{board_address:#x}"),
        "found board address"
    );

    match &cli.subcommand {
        CliSubcommand::Dump(cmd) => {
            dump(cmd, pid, ipmi_base, board_address).context("failed to dump the fan curves")?
        }
        CliSubcommand::Patch(cmd) => {
            patch(cmd, pid, ipmi_base, board_address).context("failed to patch fan curves")?
        }
    }

    Ok(())
}

fn dump(cmd: &DumpCommand, pid: Pid, ipmi_base: u32, board_address: u32) -> Result<()> {
    const PWM_REGIONS_PTR_OFFSET: u32 = 980;
    const NUM_PWM_REGIONS_OFFSET: u32 = 984;
    const PWM_REGION_SIZE: u32 = 1908;
    const PWM_REGION_ENTRY_SIZE: u32 = 76;
    const TABLE_TN_PTR_OFFSET: u32 = 32;
    const TABLE_PN_PTR_OFFSET: u32 = 48;

    let pwm_regions_ptr_addr = board_address + PWM_REGIONS_PTR_OFFSET;
    let num_pwm_regions_addr = board_address + NUM_PWM_REGIONS_OFFSET;

    let res = ptrace::read(pid, pwm_regions_ptr_addr as *mut c_void)?;
    let pwm_regions_ptr = res as u32;

    let res = ptrace::read(pid, num_pwm_regions_addr as *mut c_void)?;
    let num_pwm_regions = res as u8;

    info!(
        pwm_regions_ptr = format_args!("{pwm_regions_ptr:#x}"),
        num_pwm_regions, "read pwm region info"
    );

    let mut tables: Vec<Table> = Vec::<Table>::new();
    let mut tn_to_table = HashMap::new();
    let mut pn_to_table = HashMap::new();

    // Check if the user gave a specific list of zones to dump.
    if let Some(zones) = cmd.zone.as_ref() {
        // Make sure that all zones are in bounds.
        for zone in zones.iter().copied() {
            if zone >= num_pwm_regions {
                bail!("zone {zone} doesn't exist");
            }
        }
    }

    for zone in 0..num_pwm_regions {
        // Check if the user gave a specific list of zones to dump.
        if let Some(zones) = cmd.zone.as_ref() {
            // Check if we need to skip this zone.
            if !zones.contains(&zone) {
                continue;
            }
        }

        let pwm_region_addr = pwm_regions_ptr + u32::from(zone) * PWM_REGION_SIZE;

        for entry_idx in 0.. {
            let region_entry_addr = pwm_region_addr + 4 + entry_idx * PWM_REGION_ENTRY_SIZE;

            let mut regex = [0; 33];
            for (chunk, offset) in regex.chunks_exact_mut(4).zip((0..).step_by(4)) {
                let chunk_addr = region_entry_addr + offset;
                let res = ptrace::read(pid, chunk_addr as *mut c_void)?;
                chunk.copy_from_slice(&res.to_ne_bytes());
            }
            let zero_byte = regex.iter().copied().position(|b| b == 0).unwrap();

            let regex = CStr::from_bytes_with_nul(&regex[..=zero_byte])?;
            let regex = regex.to_str()?;
            if regex == "END_OF_ENTRY" {
                break;
            }

            // Check if the user gave a specific list of sensors to dump.
            let regex = regex.to_string();
            if let Some(sensors) = cmd.sensor.as_ref() {
                // Check if we need to skip this fan mode.
                if !sensors.contains(&regex) {
                    continue;
                }
            }

            // Read the addresses to the tn and pn tables.
            let table_tn_ptr_addr = region_entry_addr + TABLE_TN_PTR_OFFSET;
            let table_tn_ptr = ptrace::read(pid, table_tn_ptr_addr as *mut c_void)?;
            let table_tn_ptr = table_tn_ptr as u32;
            let table_pn_ptr_addr = region_entry_addr + TABLE_PN_PTR_OFFSET;
            let table_pn_ptr = ptrace::read(pid, table_pn_ptr_addr as *mut c_void)?;
            let table_pn_ptr = table_pn_ptr as u32;

            // Check if we already dumped those tables.
            match (
                tn_to_table.entry(table_tn_ptr),
                pn_to_table.entry(table_pn_ptr),
            ) {
                (Entry::Occupied(entry_tn), Entry::Occupied(entry_pn)) => {
                    // We already know those tables.

                    // Ensure that the tables are uniquely paired up and point
                    // to a single `Table` index.
                    let tn_indx = *entry_tn.get();
                    let pn_idx = *entry_pn.get();
                    ensure!(
                        tn_indx == pn_idx,
                        "tn and pn tables are not uniquely paired up"
                    );

                    // Add the info for this sensor.
                    let table: &mut Table = &mut tables[tn_indx];
                    table.info.zones.insert(zone);
                    table.info.sensors.insert(regex.to_owned());
                }
                (Entry::Vacant(entry_tn), Entry::Vacant(entry_pn)) => {
                    // We don't know about these tables yet.

                    let tn_offset = table_tn_ptr - ipmi_base;
                    let pn_offset = table_pn_ptr - ipmi_base;

                    let mut zones = BTreeSet::new();
                    zones.insert(zone);

                    let mut sensors = BTreeSet::new();
                    sensors.insert(regex.to_owned());

                    let mut curves = BTreeMap::new();
                    for fan_mode in FanMode::all() {
                        // Check if the user gave a specific list of fan modes to dump.
                        if let Some(fan_modes) = cmd.fan_mode.as_ref() {
                            // Check if we need to skip this fan mode.
                            if !fan_modes.contains(&fan_mode) {
                                continue;
                            }
                        }

                        // Dump the tn and pn curves.
                        let tn_addr = table_tn_ptr + fan_mode as u32 * 4;
                        let tn = ptrace::read(pid, tn_addr as *mut c_void)?;
                        let tn = tn.to_ne_bytes();
                        let pn_addr = table_pn_ptr + fan_mode as u32 * 4;
                        let pn = ptrace::read(pid, pn_addr as *mut c_void)?;
                        let pn = pn.to_ne_bytes();
                        curves.insert(fan_mode, Curve { tn, pn });
                    }

                    let value = Table {
                        tn_offset,
                        pn_offset,
                        info: Info { zones, sensors },
                        curves,
                    };

                    // Associate both addresses with this table.
                    let idx = tables.len();
                    tables.push(value);
                    entry_tn.insert(idx);
                    entry_pn.insert(idx);
                }
                (Entry::Occupied(_), Entry::Vacant(_)) | (Entry::Vacant(_), Entry::Occupied(_)) => {
                    // We don't know either the tn or pn table -> They are not uniquely paired up.
                    bail!("tn and pn tables are not uniquely paired up");
                }
            }
        }
    }

    let board_offset = board_address - ipmi_base;
    // Construct the config.
    let config = PwmConfig {
        board_offset,
        tables,
    };

    let str = serde_yaml::to_string(&config)?;
    if let Some(path) = cmd.file.as_ref() {
        std::fs::write(path, str).context("failed to write results to file")?;
        info!(path = %path.display(), "wrote results to file");
    } else {
        println!("{str}");
    }

    Ok(())
}

fn patch(cmd: &PatchCommand, pid: Pid, ipmi_base: u32, board_address: u32) -> Result<()> {
    let config = std::fs::read_to_string(&cmd.file).context("failed to read dump from file")?;
    let config: PwmConfig = serde_yaml::from_str(&config).context("failed to deserialize dump")?;

    let board_offset = board_address - ipmi_base;
    ensure!(
        config.board_offset == board_offset,
        "board offsets don't match up"
    );

    for table in config.tables.iter() {
        let table_tn_ptr = ipmi_base + table.tn_offset;
        let table_pn_ptr = ipmi_base + table.pn_offset;

        for (&fan_mode, curve) in table.curves.iter() {
            for &pn in curve.pn.iter() {
                ensure!(pn <= 100, "the fan duty should be within [0..100]");
            }

            // Patch the curves.
            let tn_addr = table_tn_ptr + fan_mode as u32 * 4;
            let tn = u32::from_ne_bytes(curve.tn);
            unsafe {
                // SAFETY: Yolo?!?
                ptrace::write(pid, tn_addr as *mut c_void, tn as *mut c_void)?;
            }

            let pn_addr = table_pn_ptr + fan_mode as u32 * 4;
            let pn = u32::from_ne_bytes(curve.pn);
            unsafe {
                // SAFETY: Yolo?!?
                ptrace::write(pid, pn_addr as *mut c_void, pn as *mut c_void)?;
            }
        }
    }

    info!("Patched fan curves");

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ValueEnum)]
pub enum FanMode {
    Standard,
    Full,
    Optimal,
    Pue2,
    HeavyIO,
    Pue3,
    Liquid,
    Smart,
}

impl FanMode {
    fn all() -> [Self; 8] {
        [
            Self::Standard,
            Self::Full,
            Self::Optimal,
            Self::Pue2,
            Self::HeavyIO,
            Self::Pue3,
            Self::Liquid,
            Self::Smart,
        ]
    }
}

#[derive(Serialize, Deserialize)]
pub struct PwmConfig {
    board_offset: u32,
    tables: Vec<Table>,
}

#[derive(Serialize, Deserialize)]
pub struct Table {
    tn_offset: u32,
    pn_offset: u32,
    info: Info,
    curves: BTreeMap<FanMode, Curve>,
}

pub struct Curve {
    tn: [u8; 4],
    pn: [u8; 4],
}

impl Serialize for Curve {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(4))?;
        for (tn, pn) in self.tn.into_iter().zip(self.pn) {
            map.serialize_entry(&tn, &pn)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for Curve {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CurveVisitor;

        impl<'de> Visitor<'de> for CurveVisitor {
            type Value = Curve;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a map of 4 temperatures and fan duties")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut tn = [0; 4];
                let mut pn = [0; 4];

                for (i, (tn, pn)) in tn.iter_mut().zip(pn.iter_mut()).enumerate() {
                    let (new_tn, new_pn) = map
                        .next_entry()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                    *tn = new_tn;
                    *pn = new_pn;
                }

                Ok(Curve { tn, pn })
            }
        }

        deserializer.deserialize_map(CurveVisitor)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Info {
    zones: BTreeSet<u8>,
    sensors: BTreeSet<String>,
}
