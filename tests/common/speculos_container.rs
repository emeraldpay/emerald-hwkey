// Copyright 2025 EmeraldPay, Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Helper module for managing Speculos container in tests

use crate::Speculos;
use crate::LedgerSpeculosKey;
use emerald_hwkey::ledger::connect::LedgerKey;

use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use testcontainers::core::{WaitFor, ContainerPort, IntoContainerPort};
use testcontainers::runners::AsyncRunner;
use testcontainers::core::wait::LogWaitStrategy;
use std::collections::HashMap;
use std::sync::mpsc;
use std::time::Duration;

/// Configuration for Speculos container
pub struct SpeculosConfig {
    pub app_path: String,
    pub model: String,
    pub display: String,
    pub sdk: String,
    pub mount_binaries: bool,
}

impl Default for SpeculosConfig {
    fn default() -> Self {
        Self {
            app_path: "apps/btc.elf".to_string(),
            model: "nanox".to_string(),
            display: "headless".to_string(),
            sdk: "2.0".to_string(),
            mount_binaries: true,
        }
    }
}

impl SpeculosConfig {
    pub fn ethereum() -> Self {
        Self {
            app_path: "apps/ethereum-nanox-2.0.2-1.9.18.elf".to_string(),
            ..Default::default()
        }
    }

    pub fn bitcoin() -> Self {
        Self {
            app_path: "apps/btc.elf".to_string(),
            mount_binaries: false,
            model: "nanos".to_string(),
            ..Default::default()
        }
    }

    pub fn bitcoin_test() -> Self {
        Self {
            app_path: "apps/nanos#btc-test#2.1#1c8db8da.elf".to_string(),
            model: "nanos".to_string(),
            sdk: "2.1".to_string(),
            ..Self::bitcoin()
        }
    }

    /// Run Speculos as Nano S
    pub fn with_nano_s(mut self) -> Self {
        self.model = "nanos".to_string();
        self
    }

    /// Run Speculos as Nano X
    pub fn with_nano_x(mut self) -> Self {
        self.model = "nanox".to_string();
        self
    }

    /// Set the app
    pub fn with_app(mut self, app_path: &str) -> Self {
        self.app_path = app_path.to_string();
        self
    }

    pub fn with_sdk(mut self, sdk: &str) -> Self {
        self.sdk = sdk.to_string();
        self
    }

    pub fn with_sdk_v1(self) -> Self {
        self.with_sdk("1.6")
    }

    pub fn with_sdk_v2(self) -> Self {
        self.with_sdk("2.1")
    }
}

/// Start a Speculos container with the given configuration
pub async fn start_speculos_container(config: SpeculosConfig) -> Result<ContainerAsync<GenericImage>, testcontainers::TestcontainersError> {
    let args = vec![
        "--display".to_string(),
        config.display,
        "--model".to_string(),
        config.model,
        "--sdk".to_string(),
        config.sdk,
        config.app_path,
    ];

    let mut image = GenericImage::new("ghcr.io/ledgerhq/speculos", "latest")
        .with_exposed_port(ContainerPort::Tcp(5000))
        .with_wait_for(WaitFor::Log(LogWaitStrategy::stdout_or_stderr("[*] Seed initialized")))
        .with_cmd(args);

    if config.mount_binaries {
        // Mount the testdata directory for Ledger apps
        let current_dir = std::env::current_dir().expect("Failed to get current directory");
        let testdata_path = current_dir.join("testdata/ledger-elf");
        image = image.with_mount(testcontainers::core::Mount::bind_mount(
            testdata_path.to_string_lossy().to_string(),
            "/speculos/apps"
        ));
    }

    image.start().await
}

pub async fn start_speculos_client(config: SpeculosConfig) -> Result<(Speculos, LedgerSpeculosKey, ContainerAsync<GenericImage>), testcontainers::TestcontainersError> {
    let container = start_speculos_container(config).await?;
    // Get the container connection details
    let host = container.get_host().await.unwrap().to_string();
    let port = container.get_host_port_ipv4(5000).await.unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut manager = LedgerSpeculosKey::new(&host, port).unwrap();
    manager.connect().expect("Not connected");
    let speculos = Speculos::new(&host, port);


    Ok((speculos, manager, container))
}